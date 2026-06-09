import os
import json
import shutil
import subprocess
import logging
from celery import shared_task, chain
from django.conf import settings
from apps.rootfs.models import RootFS, ScanLog
from apps.organizations.models import Product, BusinessUnit, UserBUMembership
from apps.sbom.models import SbomUpload

logger = logging.getLogger(__name__)

ROOTFS_DIR = '/rootfs'
MEDIA_ROOT = settings.MEDIA_ROOT


def _log(rootfs, stage, message, level='INFO'):
    ScanLog.objects.create(rootfs=rootfs, stage=stage, message=message, level=level)
    getattr(logger, level.lower())(f"[{stage}] {message}")


@shared_task(
    name="process_rauc_task",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    time_limit=1800,       # 30 min hard limit
    soft_time_limit=1680,  # 28 min soft limit
    queue='rauc',
)
def process_rauc_task(self, rootfs_id):
    """
    Full RAUC bundle processing pipeline:
    1. unsquashfs → extract squashfs-root/
    2. mount -o loop *.ext4 → mnt/
    3. syft dir:mnt/ → sbom.json
    4. umount + partial cleanup
    5. process_sbom_task → standard vulnerability pipeline
    6. final cleanup
    """
    rootfs = RootFS.objects.get(id=rootfs_id)
    work_dir = os.path.join(ROOTFS_DIR, str(rootfs.internal_name))
    squashfs_dir = os.path.join(work_dir, 'squashfs-root')
    mount_dir = os.path.join(work_dir, 'mnt')
    raucb_path = rootfs.file_path

    succeeded = False
    loop_dev = None
    try:
        os.makedirs(work_dir, exist_ok=True)
        os.makedirs(mount_dir, exist_ok=True)

        # ── STEP 1: unsquashfs ──────────────────────────────────────────
        rootfs.scan_status = 'GENERATING_SBOM'
        rootfs.save()
        _log(rootfs, 'UNSQUASHFS_START', f'Extraindo {raucb_path}')

        result = subprocess.run(
            ['unsquashfs', '-d', squashfs_dir, '-f', raucb_path],
            capture_output=True, text=True
        )
        if result.returncode not in (0, 2):  # 2 = non-fatal warnings
            raise RuntimeError(f'unsquashfs falhou: {result.stderr}')

        _log(rootfs, 'UNSQUASHFS_DONE', 'Extração concluída')

        # ── Read the manifest and update the product ─────────────────────
        manifest_path = os.path.join(squashfs_dir, 'manifest.raucm')
        if os.path.exists(manifest_path):
            import configparser
            config = configparser.ConfigParser()
            config.read(manifest_path)

            if 'update' in config:
                compatible = config['update'].get('compatible', '')
                version = config['update'].get('version', '')

                if compatible:
                    from apps.organizations.models import BusinessUnit
                    bu = rootfs.product.business_unit

                    real_product, created = Product.objects.get_or_create(
                        name=compatible,
                        business_unit=bu,
                        defaults={
                            'version': version,
                            'active': True,
                        }
                    )
                    if not created and not real_product.active:
                        real_product.active = True
                        real_product.save()

                    old_product = rootfs.product
                    rootfs.product = real_product
                    rootfs.save()

                    if old_product.name.startswith('rauc-'):
                        old_product.delete()

                    _log(rootfs, 'MANIFEST_READ', f'Produto: {compatible} v{version}')

            for section in config.sections():
                if section.startswith('image.'):
                    sha256 = config[section].get('sha256', '')
                    if sha256:
                        rootfs.sha256 = sha256
                        rootfs.save()
                    break

        # ── STEP 2: Locate the .ext4 image ──────────────────────────────
        ext4_file = None
        for f in os.listdir(squashfs_dir):
            if f.endswith('.ext4'):
                ext4_file = os.path.join(squashfs_dir, f)
                break

        if not ext4_file:
            raise RuntimeError('Arquivo .ext4 não encontrado no bundle')

        _log(rootfs, 'EXT4_FOUND', f'Imagem encontrada: {os.path.basename(ext4_file)}')

        # ── STEP 3: losetup + mount ──────────────────────────────────────
        #
        # Pré-requisito no host: loop devices suficientes para o número de
        # workers paralelos. O padrão do kernel costuma ser 8. Para aumentar:
        #   sudo modprobe loop max_loop=64
        #   echo "options loop max_loop=64" > /etc/modprobe.d/loop.conf
        #
        # Por que NÃO usamos `mount -o loop ext4_file mount_dir` diretamente:
        #
        #   Esse atalho pede ao kernel para alocar automaticamente um loop
        #   device livre via /dev/loop-control. Dentro de containers Docker
        #   — mesmo com `privileged: true` — essa alocação automática falha
        #   de forma intermitente com "failed to setup loop device", porque
        #   o /dev/loop-control pode não estar acessível ou o kernel pode
        #   recusar a criação de novos loop devices no namespace do container.
        #
        # Solução: dois passos explícitos com losetup:
        #
        #   1. `losetup -f --show -r <arquivo>`
        #        -f       → encontra o próximo loop device livre
        #        --show   → imprime o caminho do device alocado (ex: /dev/loop3)
        #        -r       → anexa em modo read-only (seguro para leitura de imagem)
        #      Essa operação é atômica: encontrar + anexar acontece em uma única
        #      syscall, eliminando a race condition do `mount -o loop`.
        #
        #   2. `mount -t ext4 -o ro <loop_dev> <mount_dir>`
        #      Monta o block device diretamente, sem passar pelo loop-control.
        #      O kernel trata /dev/loopN como qualquer outro block device.
        #
        # Cleanup: `losetup -d <loop_dev>` deve ser chamado após umount para
        #   liberar o loop device. Isso é feito tanto no fluxo normal (step 5)
        #   quanto no bloco `finally`, garantindo que retries não vazem devices.
        #
        _log(rootfs, 'MOUNT_START', f'Montando {ext4_file}')

        lo_result = subprocess.run(
            ['losetup', '-f', '--show', '-r', ext4_file],
            capture_output=True, text=True
        )
        if lo_result.returncode != 0:
            err = lo_result.stderr.strip()
            if 'no free loop devices' in err:
                raise RuntimeError(
                    'Sem loop devices livres no host. '
                    'Aumente o limite: modprobe loop max_loop=64'
                )
            raise RuntimeError(f'losetup falhou: {err}')
        loop_dev = lo_result.stdout.strip()

        result = subprocess.run(
            ['mount', '-t', 'ext4', '-o', 'ro', loop_dev, mount_dir],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            # Libera o loop device imediatamente para não vazar em caso de
            # erro no mount (o finally também tentará, mas loop_dev=None evita
            # dupla chamada).
            subprocess.run(['losetup', '-d', loop_dev], capture_output=True)
            loop_dev = None
            raise RuntimeError(f'mount falhou: {result.stderr}')

        _log(rootfs, 'MOUNT_DONE', f'Montado em {mount_dir} via {loop_dev}')

        # ── STEP 4: syft ────────────────────────────────────────────────
        _log(rootfs, 'SYFT_START', 'Gerando SBOM com Syft')

        from django.utils import timezone
        now = timezone.now()
        sbom_relative = f"sboms/{now.strftime('%Y/%m/%d')}/{rootfs_id}.json"
        sbom_path = os.path.join(MEDIA_ROOT, sbom_relative)
        os.makedirs(os.path.dirname(sbom_path), exist_ok=True)

        result = subprocess.run(
            ['syft', f'dir:{mount_dir}', '-o', 'cyclonedx-json'],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f'syft falhou: {result.stderr}')

        with open(sbom_path, 'w') as f:
            f.write(result.stdout)

        _log(rootfs, 'SYFT_DONE', f'SBOM gerado: {sbom_path}')

        # ── STEP 5: umount + losetup detach ─────────────────────────────
        # umount primeiro, depois losetup -d: o kernel rejeita -d enquanto
        # o device ainda estiver montado.
        subprocess.run(['umount', mount_dir], capture_output=True)
        if loop_dev:
            subprocess.run(['losetup', '-d', loop_dev], capture_output=True)
            loop_dev = None  # evita double-free no finally
        _log(rootfs, 'UMOUNT_DONE', 'Desmontado')

        # ── STEP 6: Create SbomUpload and trigger the standard pipeline ──
        from django.core.files import File

        with open(sbom_path, 'rb') as f:
            upload = SbomUpload.objects.create(
                product=rootfs.product,
                product_name=rootfs.product.name,
                status='PENDING'
            )
            upload.sbom_file.save(f"{rootfs_id}.json", File(f), save=True)

        _log(rootfs, 'SBOM_UPLOAD_CREATED', f'SbomUpload criado: {upload.id}')

        from tasks.sbom_tasks import process_sbom_task
        process_sbom_task.delay(str(upload.id))

        rootfs.scan_status = 'COMPLETED'
        rootfs.save()
        succeeded = True

    except Exception as e:
        from celery.exceptions import SoftTimeLimitExceeded
        logger.error(f'[process_rauc_task] Erro: {str(e)}')
        rootfs.scan_status = 'ERROR'
        rootfs.save()
        _log(rootfs, 'ERROR', str(e), level='ERROR')

        if isinstance(e, SoftTimeLimitExceeded):
            # não faz retry — cai direto no finally
            raise

        raise self.retry(exc=e, countdown=120 * (self.request.retries + 1))

    finally:
        # ── CLEANUP GARANTIDO — sempre executa, sucesso ou erro ──────────
        # Garante que umount + losetup -d rodem mesmo em exceções ou retries,
        # evitando que loop devices fiquem presos entre tentativas.
        subprocess.run(['umount', mount_dir], capture_output=True)
        if loop_dev:
            subprocess.run(['losetup', '-d', loop_dev], capture_output=True)

        # Remove temporários sempre (squashfs-root e mnt)
        shutil.rmtree(squashfs_dir, ignore_errors=True)
        shutil.rmtree(mount_dir, ignore_errors=True)

        # Remove o .raucb original apenas em sucesso ou última tentativa
        is_last_attempt = self.request.retries >= self.max_retries
        if succeeded or is_last_attempt:
            if os.path.exists(raucb_path):
                os.remove(raucb_path)
            _log(rootfs, 'CLEANUP_DONE', 'Arquivos temporários removidos')