import os
import hashlib
import logging
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from apps.rootfs.models import RootFS, ScanLog
from apps.organizations.models import Product, UserBUMembership
from django.views.decorators.http import require_http_methods
from apps.accounts.permissions import administrador_required, operador_required
from core.mongo import log_audit, log_error

logger = logging.getLogger(__name__)

ROOTFS_DIR = '/rootfs'
UPLOAD_DIR = '/data/uploads'


@login_required
@operador_required
def upload_rauc_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método não permitido'}, status=405)

    chunk = request.FILES.get('file')
    upload_id = request.POST.get('upload_id')
    chunk_index = int(request.POST.get('chunk_index', 0))
    total_chunks = int(request.POST.get('total_chunks', 1))
    filename = request.POST.get('filename', 'upload.raucb')

    if not chunk or not upload_id:
        return JsonResponse({'error': 'Dados inválidos'}, status=400)

    tmp_dir = os.path.join(UPLOAD_DIR, 'rauc_tmp', upload_id)
    os.makedirs(tmp_dir, exist_ok=True)
    chunk_path = os.path.join(tmp_dir, f'chunk_{chunk_index:05d}')

    with open(chunk_path, 'wb') as f:
        for part in chunk.chunks():
            f.write(part)

    if chunk_index + 1 < total_chunks:
        return JsonResponse({'status': 'chunk_ok', 'chunk': chunk_index, 'total': total_chunks})

    # ── ÚLTIMO CHUNK ────────────────────────────────────────────────────────
    final_path = os.path.join(ROOTFS_DIR, f'{upload_id}_{filename}')

    try:
        with open(final_path, 'wb') as final_file:
            for i in range(total_chunks):
                part_path = os.path.join(tmp_dir, f'chunk_{i:05d}')
                with open(part_path, 'rb') as part:
                    final_file.write(part.read())
                os.remove(part_path)
        os.rmdir(tmp_dir)

        # ── Calcula hash do arquivo .raucb completo ──────────────────────
        hasher = hashlib.sha256()
        with open(final_path, 'rb') as f:
            for block in iter(lambda: f.read(8192), b''):
                hasher.update(block)
        bundle_hash = hasher.hexdigest()

       # Verifica duplicata pelo hash do bundle
        existing = RootFS.objects.filter(
            bundle_hash=bundle_hash,
            is_active=True
        ).exclude(scan_status='ERROR').first()

        if existing:
            os.remove(final_path)
            return JsonResponse({
                'status': 'duplicate',
                'message': 'Este bundle RAUC já foi processado anteriormente.',
                'existing_id': str(existing.id),
            }, status=200)

        # ── Create temporary product and RootFS (atomic to prevent duplicates) ──
        membership = UserBUMembership.objects.filter(user=request.user).first()
        user_bu = membership.business_unit if membership else None

        import uuid as uuid_module
        from django.db import transaction

        try:
            with transaction.atomic():
                # Re-check inside the transaction — prevents race condition
                # between two simultaneous uploads of the same file
                duplicate = RootFS.objects.select_for_update().filter(
                    bundle_hash=bundle_hash,
                    is_active=True
                ).exclude(scan_status='ERROR').first()

                if duplicate:
                    os.remove(final_path)
                    return JsonResponse({
                        'status': 'duplicate',
                        'message': 'Este bundle RAUC já foi processado anteriormente.',
                        'existing_id': str(duplicate.id),
                    }, status=200)

                product, _ = Product.objects.get_or_create(
                    name=f'rauc-{upload_id[:8]}',
                    business_unit=user_bu,
                    defaults={'created_by': request.user}
                )

                rootfs = RootFS.objects.create(
                    product=product,
                    filename=filename,
                    internal_name=uuid_module.uuid4(),
                    file_path=final_path,
                    bundle_hash=bundle_hash,
                    scan_status='PENDING'
                )

        except Exception as e:
            if os.path.exists(final_path):
                os.remove(final_path)
            raise e

        ScanLog.objects.create(
            rootfs=rootfs,
            stage='UPLOAD_COMPLETE',
            message=f'Bundle RAUC recebido: {filename}',
            level='INFO'
        )

        from tasks.rauc_tasks import process_rauc_task
        process_rauc_task.delay(str(rootfs.id))

        log_audit(request.user, 'UPLOAD_RAUC',
                  filename=filename,
                  rootfs_id=str(rootfs.id),
                  product=product.name,
                  bundle_hash=bundle_hash,
                  ip=request.META.get('REMOTE_ADDR'))

        return JsonResponse({
            'status': 'success',
            'message': f'Bundle RAUC {filename} em processamento!',
            'rootfs_id': str(rootfs.id),
        }, status=201)

    except Exception as e:
        logger.error(f'[upload_rauc_view] Erro: {str(e)}')
        log_error('upload_rauc_view', str(e),
                  user=request.user.username,
                  filename=filename,
                  ip=request.META.get('REMOTE_ADDR'))
        if os.path.exists(final_path):
            os.remove(final_path)
        return JsonResponse({'error': f'Erro interno: {str(e)}'}, status=500)


@login_required
def api_check_rauc_hash(request):
    bundle_hash = request.GET.get('hash', '')
    if not bundle_hash:
        return JsonResponse({'duplicate': False})
    
    existing = RootFS.objects.filter(
        bundle_hash=bundle_hash,
        is_active=True 
    ).exclude(scan_status='ERROR').first()
    
    return JsonResponse({
        'duplicate': bool(existing),
        'message': 'Este bundle RAUC já foi processado anteriormente.' if existing else ''
    })

@login_required
@require_http_methods(['POST'])
@administrador_required
def api_deactivate_rootfs_by_product(request, product_id):
    from apps.organizations.models import Product
    from django.views.decorators.http import require_http_methods

    membership = UserBUMembership.objects.filter(user=request.user).first()
    if not membership:
        return JsonResponse({'error': 'Acesso negado'}, status=403)

    RootFS.objects.filter(
        product__id=product_id,
        product__business_unit=membership.business_unit
    ).update(is_active=False)

    log_audit(request.user, 'DEACTIVATE_ROOTFS',
              product_id=product_id,
              ip=request.META.get('REMOTE_ADDR'))

    return JsonResponse({'status': 'deactivated'})

@login_required
@operador_required
def upload_ext4_view(request):
    """Upload chunked de arquivo .ext4 avulso."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Método não permitido'}, status=405)

    chunk = request.FILES.get('file')
    upload_id = request.POST.get('upload_id')
    chunk_index = int(request.POST.get('chunk_index', 0))
    total_chunks = int(request.POST.get('total_chunks', 1))
    filename = request.POST.get('filename', 'image.ext4')

    if not chunk or not upload_id:
        return JsonResponse({'error': 'Dados inválidos'}, status=400)

    tmp_dir = os.path.join(UPLOAD_DIR, 'ext4_tmp', upload_id)
    os.makedirs(tmp_dir, exist_ok=True)
    chunk_path = os.path.join(tmp_dir, f'chunk_{chunk_index:05d}')

    with open(chunk_path, 'wb') as f:
        for part in chunk.chunks():
            f.write(part)

    if chunk_index + 1 < total_chunks:
        return JsonResponse({'status': 'chunk_ok', 'chunk': chunk_index, 'total': total_chunks})

    final_path = os.path.join(ROOTFS_DIR, f'{upload_id}_{filename}')

    try:
        with open(final_path, 'wb') as final_file:
            for i in range(total_chunks):
                part_path = os.path.join(tmp_dir, f'chunk_{i:05d}')
                with open(part_path, 'rb') as part:
                    final_file.write(part.read())
                os.remove(part_path)
        os.rmdir(tmp_dir)

        hasher = hashlib.sha256()
        with open(final_path, 'rb') as f:
            for block in iter(lambda: f.read(8192), b''):
                hasher.update(block)
        bundle_hash = hasher.hexdigest()

        existing = RootFS.objects.filter(
            bundle_hash=bundle_hash,
            is_active=True
        ).exclude(scan_status='ERROR').first()

        if existing:
            os.remove(final_path)
            return JsonResponse({
                'status': 'duplicate',
                'message': 'Este arquivo .ext4 já foi processado anteriormente.',
                'existing_id': str(existing.id),
            }, status=200)

        membership = UserBUMembership.objects.filter(user=request.user).first()
        user_bu = membership.business_unit if membership else None

        import uuid as uuid_module
        from django.db import transaction

        with transaction.atomic():
            duplicate = RootFS.objects.select_for_update().filter(
                bundle_hash=bundle_hash,
                is_active=True
            ).exclude(scan_status='ERROR').first()

            if duplicate:
                os.remove(final_path)
                return JsonResponse({
                    'status': 'duplicate',
                    'message': 'Este arquivo .ext4 já foi processado anteriormente.',
                    'existing_id': str(duplicate.id),
                }, status=200)

            product, _ = Product.objects.get_or_create(
                name=f'ext4-{bundle_hash[:16]}',
                business_unit=user_bu,
                defaults={'created_by': request.user}
            )

            rootfs = RootFS.objects.create(
                product=product,
                filename=filename,
                internal_name=uuid_module.uuid4(),
                file_path=final_path,
                bundle_hash=bundle_hash,
                scan_status='PENDING'
            )

        ScanLog.objects.create(
            rootfs=rootfs,
            stage='UPLOAD_COMPLETE',
            message=f'Arquivo .ext4 recebido: {filename}',
            level='INFO'
        )

        from tasks.ext4_tasks import process_ext4_task
        process_ext4_task.delay(str(rootfs.id))

        log_audit(request.user, 'UPLOAD_EXT4',
                  filename=filename,
                  rootfs_id=str(rootfs.id),
                  product=product.name,
                  bundle_hash=bundle_hash,
                  ip=request.META.get('REMOTE_ADDR'))

        return JsonResponse({
            'status': 'success',
            'message': f'Arquivo .ext4 {filename} em processamento!',
            'rootfs_id': str(rootfs.id),
        }, status=201)

    except Exception as e:
        logger.error(f'[upload_ext4_view] Erro: {str(e)}')
        log_error('upload_ext4_view', str(e),
                  user=request.user.username,
                  filename=filename,
                  ip=request.META.get('REMOTE_ADDR'))
        if os.path.exists(final_path):
            os.remove(final_path)
        return JsonResponse({'error': f'Erro interno: {str(e)}'}, status=500)