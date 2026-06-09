import os
import shutil
import subprocess
import logging
from celery import shared_task
from django.conf import settings
from apps.rootfs.models import RootFS, ScanLog
from apps.organizations.models import Product
from apps.sbom.models import SbomUpload

logger = logging.getLogger(__name__)

ROOTFS_DIR = '/rootfs'
MEDIA_ROOT = settings.MEDIA_ROOT


def _log(rootfs, stage, message, level='INFO'):
    ScanLog.objects.create(rootfs=rootfs, stage=stage, message=message, level=level)
    getattr(logger, level.lower())(f"[{stage}] {message}")


def _read_os_release(mount_dir):
    """
    Lê /etc/os-release do filesystem montado.
    Retorna (name, version) ou (None, None) se não encontrar.
    """
    os_release_path = os.path.join(mount_dir, 'etc', 'os-release')
    if not os.path.exists(os_release_path):
        # Tenta /usr/lib/os-release como fallback
        os_release_path = os.path.join(mount_dir, 'usr', 'lib', 'os-release')
        if not os.path.exists(os_release_path):
            return None, None

    name = None
    version = None
    try:
        with open(os_release_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('NAME='):
                    name = line.split('=', 1)[1].strip().strip('"\'')
                elif line.startswith('VERSION=') or line.startswith('VERSION_ID='):
                    if not version:  # VERSION tem prioridade sobre VERSION_ID
                        version = line.split('=', 1)[1].strip().strip('"\'')
    except Exception as e:
        logger.warning(f'[_read_os_release] Erro ao ler os-release: {e}')

    return name, version


@shared_task(
    name="process_ext4_task",
    bind=True,
    max_retries=2,
    default_retry_delay=120,
    time_limit=1800,
    soft_time_limit=1680,
    queue='rauc',  # usa a mesma fila dedicada para evitar sobrecarga de loop devices
)
def process_ext4_task(self, rootfs_id):
    """
    Pipeline de processamento de imagem .ext4 avulsa:
    1. mount -o loop .ext4 → mnt/
    2. Lê /etc/os-release → extrai nome e versão do produto
    3. Se não encontrar → usa SHA256 do arquivo como nome
    4. syft dir:mnt/ → sbom.json (CycloneDX)
    5. umount + cleanup
    6. process_sbom_task → pipeline normal de vulnerabilidades
    """
    rootfs = RootFS.objects.get(id=rootfs_id)
    work_dir = os.path.join(ROOTFS_DIR, str(rootfs.internal_name))
    mount_dir = os.path.join(work_dir, 'mnt')
    ext4_path = rootfs.file_path

    try:
        os.makedirs(work_dir, exist_ok=True)
        os.makedirs(mount_dir, exist_ok=True)

        rootfs.scan_status = 'GENERATING_SBOM'
        rootfs.save()

        # ── ETAPA 1: mount -o loop ───────────────────────────────────────
        _log(rootfs, 'MOUNT_START', f'Montando {ext4_path}')

        result = subprocess.run(
            ['mount', '-o', 'loop', ext4_path, mount_dir],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f'mount falhou: {result.stderr}')

        _log(rootfs, 'MOUNT_DONE', f'Montado em {mount_dir}')

        # ── ETAPA 2: Lê /etc/os-release ─────────────────────────────────
        product_name, product_version = _read_os_release(mount_dir)

        if product_name:
            _log(rootfs, 'OS_RELEASE_FOUND', f'Produto: {product_name} v{product_version or "?"}')
        else:
            # Fallback: usa os primeiros 16 chars do hash SHA256
            product_name = f'ext4-{rootfs.bundle_hash[:16]}'
            product_version = None
            _log(rootfs, 'OS_RELEASE_NOT_FOUND',
                 f'os-release não encontrado — usando hash: {product_name}',
                 level='WARNING')

        # ── ETAPA 3: Atualiza o produto com o nome real ──────────────────
        bu = rootfs.product.business_unit
        old_product = rootfs.product

        real_product, created = Product.objects.get_or_create(
            name=product_name,
            business_unit=bu,
            defaults={
                'version': product_version or '',
                'active': True,
            }
        )
        if not created and not real_product.active:
            real_product.active = True
            real_product.save()

        rootfs.product = real_product
        rootfs.save()

        # Remove produto temporário ext4-XXXX
        if old_product.name.startswith('ext4-') and old_product.id != real_product.id:
            old_product.delete()

        _log(rootfs, 'PRODUCT_UPDATED', f'Produto definido: {real_product.name}')

        # ── ETAPA 4: Syft ────────────────────────────────────────────────
        _log(rootfs, 'SYFT_START', 'Gerando SBOM com Syft')

        from django.utils import timezone
        now = timezone.now()
        sbom_relative = f"sboms/{now.strftime('%Y/%m/%d')}/{rootfs_id}.json"
        sbom_path = os.path.join(MEDIA_ROOT, sbom_relative)
        os.makedirs(os.path.dirname(sbom_path), exist_ok=True)

        result = subprocess.run(
            ['syft', f'dir:{mount_dir}', '-o', 'cyclonedx-json'],
            capture_output=True, text=True,
            timeout=1200,  # 20 min para filesystems grandes
        )
        if result.returncode != 0:
            raise RuntimeError(f'syft falhou: {result.stderr}')

        with open(sbom_path, 'w') as f:
            f.write(result.stdout)

        _log(rootfs, 'SYFT_DONE', f'SBOM gerado: {sbom_path}')

        # ── ETAPA 5: umount ──────────────────────────────────────────────
        subprocess.run(['umount', mount_dir], capture_output=True)
        _log(rootfs, 'UMOUNT_DONE', 'Desmontado')

        # ── ETAPA 6: Cria SbomUpload e dispara pipeline normal ───────────
        from django.core.files import File

        with open(sbom_path, 'rb') as f:
            upload = SbomUpload.objects.create(
                product=rootfs.product,
                product_name=rootfs.product.name,
                status='PENDING',
                source='upload',
            )
            upload.sbom_file.save(f"{rootfs_id}.json", File(f), save=True)

        _log(rootfs, 'SBOM_UPLOAD_CREATED', f'SbomUpload criado: {upload.id}')

        from tasks.sbom_tasks import process_sbom_task
        process_sbom_task.delay(str(upload.id))

        # ── ETAPA 7: Cleanup ─────────────────────────────────────────────
        shutil.rmtree(work_dir, ignore_errors=True)
        if os.path.exists(ext4_path):
            os.remove(ext4_path)

        rootfs.scan_status = 'COMPLETED'
        rootfs.save()
        _log(rootfs, 'CLEANUP_DONE', 'Arquivos temporários removidos')

    except Exception as e:
        from celery.exceptions import SoftTimeLimitExceeded
        logger.error(f'[process_ext4_task] Erro: {str(e)}')
        rootfs.scan_status = 'ERROR'
        rootfs.save()
        _log(rootfs, 'ERROR', str(e), level='ERROR')
        subprocess.run(['umount', mount_dir], capture_output=True)
        if isinstance(e, SoftTimeLimitExceeded):
            raise
        raise self.retry(exc=e, countdown=120 * (self.request.retries + 1))