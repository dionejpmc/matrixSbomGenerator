"""
apps/sbom/csv_views.py

Views para upload manual via CSV e aprovação de SBOMs.
"""
import csv
import io
import json
import uuid
import logging
from datetime import datetime

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.utils import timezone

from .models import SbomUpload, Component
from apps.organizations.models import Product, UserBUMembership
from apps.accounts.permissions import operador_required, administrador_required
from core.mongo import log_audit, log_error

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# TEMPLATE CSV DOWNLOAD
# ─────────────────────────────────────────────────────────────

@login_required
def download_csv_template(request):
    """Baixa o template CSV para preenchimento manual de componentes."""
    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="matrix-components-template.csv"'
    response.write('\ufeff')  # BOM para Excel abrir corretamente

    writer = csv.writer(response)
    writer.writerow(['name', 'version', 'type', 'purl', 'cpe'])
    writer.writerow(['FreeRTOS', '10.4.3', 'library',
                     'pkg:generic/freertos@10.4.3',
                     'cpe:2.3:a:freertos:freertos:10.4.3:*:*:*:*:*:*:*'])
    writer.writerow(['mbedTLS', '3.1.0', 'library',
                     'pkg:github/ARMmbed/mbedtls@v3.1.0',
                     'cpe:2.3:a:arm:mbed_tls:3.1.0:*:*:*:*:*:*:*'])
    writer.writerow(['lwIP', '2.1.3', 'library',
                     'pkg:generic/lwip@2.1.3', ''])
    writer.writerow(['MinhaLib', '1.0.0', 'library', '', ''])

    return response


# ─────────────────────────────────────────────────────────────
# PARSE CSV
# ─────────────────────────────────────────────────────────────

@login_required
@operador_required
@require_http_methods(['POST'])
def api_parse_csv(request):
    """
    Recebe o CSV e retorna os componentes parseados para edição na interface.
    Não salva nada ainda — só valida e retorna os dados.
    """
    csv_file = request.FILES.get('csv_file')
    if not csv_file:
        return JsonResponse({'error': 'Arquivo CSV não enviado'}, status=400)

    try:
        content = csv_file.read().decode('utf-8-sig')  # utf-8-sig remove BOM
        reader = csv.DictReader(io.StringIO(content))

        required = {'name', 'version'}
        if not required.issubset(set(reader.fieldnames or [])):
            return JsonResponse({
                'error': f'CSV deve ter as colunas: name, version (encontrado: {reader.fieldnames})'
            }, status=400)

        components = []
        for i, row in enumerate(reader, 1):
            name = row.get('name', '').strip()
            version = row.get('version', '').strip()
            if not name or not version:
                continue

            purl = row.get('purl', '').strip()
            if not purl:
                purl = f"pkg:generic/{name}@{version}"

            components.append({
                'row': i,
                'name': name,
                'version': version,
                'type': row.get('type', 'library').strip() or 'library',
                'purl': purl,
                'cpe': row.get('cpe', '').strip(),
            })

        if not components:
            return JsonResponse({'error': 'Nenhum componente válido encontrado no CSV'}, status=400)

        return JsonResponse({'components': components, 'total': len(components)})

    except Exception as e:
        logger.error(f'[api_parse_csv] Erro: {e}')
        return JsonResponse({'error': f'Erro ao processar CSV: {str(e)}'}, status=500)


# ─────────────────────────────────────────────────────────────
# SALVAR SBOM MANUAL
# ─────────────────────────────────────────────────────────────

@login_required
@operador_required
@require_http_methods(['POST'])
def api_save_manual_sbom(request):
    """
    Salva o produto e componentes no PostgreSQL.
    Cria SbomUpload com status=VALIDATION e source=csv.
    Não gera SBOM nem dispara Grype — aguarda aprovação do admin.
    """
    try:
        data = json.loads(request.body)
        product_name = data.get('product_name', '').strip()
        product_version = data.get('product_version', '').strip()
        components = data.get('components', [])

        if not product_name:
            return JsonResponse({'error': 'Product Name required'}, status=400)
        if not product_version:
            return JsonResponse({'error': 'Product Version required'}, status=400)
        if not components:
            return JsonResponse({'error': 'No components fund in the list'}, status=400)

        membership = UserBUMembership.objects.filter(user=request.user).first()
        user_bu = membership.business_unit if membership else None

        # Check if an active product with the same name AND version already exists in the BU
        existing_product = Product.objects.filter(
            name=product_name,
            version=product_version,
            business_unit=user_bu,
            active=True,
        ).first()

        if existing_product:
            # Check if an active or pending SBOM already exists for this product
            existing_upload = SbomUpload.objects.filter(
                product=existing_product,
                status__in=['COMPLETED', 'PENDING', 'PROCESSING', 'VALIDATION'],
            ).first()
            if existing_upload:
                return JsonResponse({
                    'error': f'Já existe um SBOM para o produto "{product_name}" versão "{product_version}" com status "{existing_upload.get_status_display()}". '
                             f'Desative o produto existente antes de criar um novo.',
                    'duplicate': True,
                }, status=400)

        # Create the product — name + version as the unique key
        product, created = Product.objects.get_or_create(
            name=product_name,
            version=product_version,
            business_unit=user_bu,
            defaults={
                'created_by': request.user,
                'active': True,
            }
        )
        # Reactivate if the product already existed but was inactive
        if not created and not product.active:
            product.active = True
            product.save(update_fields=['active'])

        # Create the SbomUpload with no file attached — awaiting approval
        upload = SbomUpload.objects.create(
            product=product,
            product_name=product_name,
            status='VALIDATION',
            source='csv',
            uploaded_by=request.user,
        )

        # Fetch existing components to avoid duplicates
        existing = set(
            Component.objects.filter(product=product)
            .values_list('name', 'version')
        )

        to_create = []
        for comp_data in components:
            name = comp_data.get('name', '').strip()
            version = comp_data.get('version', '').strip()
            if not name or not version:
                continue
            if (name, version) in existing:
                continue
            to_create.append(Component(
                product=product,
                name=name,
                version=version,
                type=comp_data.get('type', 'library') or 'library',
                purl=comp_data.get('purl') or f"pkg:generic/{name}@{version}",
                cpe=comp_data.get('cpe') or None,
            ))

        Component.objects.bulk_create(to_create, ignore_conflicts=True)
        created_count = len(to_create)

        log_audit(request.user, 'CSV_MANUAL_UPLOAD',
                  upload_id=str(upload.id),
                  product_name=product_name,
                  product_version=product_version,
                  components_count=created_count,
                  ip=request.META.get('REMOTE_ADDR'))

        logger.info(f"[api_save_manual_sbom] Produto '{product_name}' criado com {created_count} componentes — aguardando aprovação")

        return JsonResponse({
            'status': 'created',
            'upload_id': str(upload.id),
            'product_id': product.id,
            'components_saved': created_count,
            'message': f'Produto "{product_name}" criado com {created_count} componentes. Aguardando aprovação do administrador.',
        }, status=201)

    except Exception as e:
        logger.error(f'[api_save_manual_sbom] Erro: {e}')
        log_error('api_save_manual_sbom', str(e), user=request.user.username)
        return JsonResponse({'error': str(e)}, status=500)


# ─────────────────────────────────────────────────────────────
# PÁGINA DE APROVAÇÃO
# ─────────────────────────────────────────────────────────────

@login_required
@administrador_required
def approval_view(request):
    """Manual SBOM approval page — administrators only."""
    return render(request, 'usuarios/approval.html')


@login_required
@administrador_required
def api_approval_list(request):
    """Lists SBOMs awaiting approval or already reviewed."""
    status_filter = request.GET.get('status', 'VALIDATION')

    uploads = SbomUpload.objects.filter(
        source='csv',
        status=status_filter,
        product__active=True,
    ).select_related('product', 'uploaded_by', 'reviewed_by').order_by('-uploaded_at')

    result = []
    for upload in uploads:
        result.append({
            'id': str(upload.id),
            'product_name': upload.product_name,
            'product_version': upload.product.version if upload.product else '',
            'product_id': upload.product.id if upload.product else None,
            'component_count': upload.product.components.count() if upload.product else 0,
            'uploaded_by': upload.uploaded_by.username if upload.uploaded_by else '—',
            'uploaded_at': upload.uploaded_at.strftime('%d/%m/%Y %H:%M'),
            'status': upload.status,
            'reviewed_by': upload.reviewed_by.username if upload.reviewed_by else None,
            'reviewed_at': upload.reviewed_at.strftime('%d/%m/%Y %H:%M') if upload.reviewed_at else None,
            'rejection_reason': upload.rejection_reason or '',
        })

    return JsonResponse({'uploads': result})


@login_required
@administrador_required
@require_http_methods(['POST'])
def api_approve_sbom(request, upload_id):
    """
    Approves a manual SBOM:
    1. Generates the CycloneDX JSON file from the components
    2. Saves the file to disk
    3. Triggers process_sbom_task → Grype → ingestion
    """
    upload = SbomUpload.objects.filter(id=upload_id, source='csv', status='VALIDATION').first()
    if not upload:
        return JsonResponse({'error': 'SBOM not found or already reviewed'}, status=404)

    # Check if the product is still active
    if not upload.product or not upload.product.active:
        return JsonResponse({
            'error': 'This product has been deactivated and can no longer be approved.'
        }, status=400)

    try:
        product = upload.product
        components = Component.objects.filter(product=product)

        # Gera CycloneDX JSON
        cyclonedx = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'version': 1,
            'serialNumber': f'urn:uuid:{str(uuid.uuid4())}',
            'metadata': {
                'timestamp': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                'tools': [{'name': 'Matrix SBOM Monitor', 'version': '1.0'}],
                'component': {
                    'type': 'firmware',
                    'name': product.name,
                    'version': product.version or '',
                },
            },
            'components': [],
        }

        for comp in components:
            entry = {
                'type': comp.type or 'library',
                'name': comp.name,
                'version': comp.version,
                'purl': comp.purl or f'pkg:generic/{comp.name}@{comp.version}',
            }
            if comp.cpe:
                entry['cpe'] = comp.cpe
            cyclonedx['components'].append(entry)

        sbom_content = json.dumps(cyclonedx, indent=2, ensure_ascii=False).encode('utf-8')

        # Verifica hash antes de persistir — evita duplicatas
        import hashlib
        file_hash = hashlib.sha256(sbom_content).hexdigest()

        existing = SbomUpload.objects.filter(
            hashcode=file_hash,
            status__in=['COMPLETED', 'PENDING', 'PROCESSING'],
            product__active=True,
        ).exclude(id=upload_id).first()

        if existing:
            logger.warning(f'[api_approve_sbom] SBOM duplicado detectado: hash={file_hash[:16]}')
            return JsonResponse({
                'error': f'Este SBOM já existe no sistema (produto: {existing.product_name}). Aprovação cancelada.',
                'duplicate': True,
                'existing_id': str(existing.id),
            }, status=400)

        # Salva o arquivo no disco
        from django.conf import settings
        from django.core.files.base import ContentFile

        filename = f"{upload.id}.json"
        upload.sbom_file.save(filename, ContentFile(sbom_content), save=False)
        upload.hashcode = file_hash
        upload.status = 'PENDING'
        upload.reviewed_by = request.user
        upload.reviewed_at = timezone.now()
        upload.save()

        # Dispara pipeline normal
        from tasks.sbom_tasks import process_sbom_task
        process_sbom_task.delay(str(upload.id))

        log_audit(request.user, 'CSV_SBOM_APPROVED',
                  upload_id=upload_id,
                  product_name=upload.product_name,
                  components=components.count())

        return JsonResponse({
            'status': 'approved',
            'message': f'SBOM aprovado. Scan de vulnerabilidades iniciado.',
        })

    except Exception as e:
        logger.error(f'[api_approve_sbom] Erro: {e}')
        log_error('api_approve_sbom', str(e), upload_id=upload_id)
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@administrador_required
@require_http_methods(['POST'])
def api_reject_sbom(request, upload_id):
    """Rejeita um SBOM manual com motivo."""
    upload = SbomUpload.objects.filter(id=upload_id, source='csv', status='VALIDATION').first()
    if not upload:
        return JsonResponse({'error': 'SBOM não encontrado ou já revisado'}, status=404)

    try:
        import json as json_lib
        data = json_lib.loads(request.body)
        reason = data.get('reason', '').strip()
        if not reason:
            return JsonResponse({'error': 'Motivo da rejeição obrigatório'}, status=400)

        upload.status = 'REJECTED'
        upload.reviewed_by = request.user
        upload.reviewed_at = timezone.now()
        upload.rejection_reason = reason
        upload.save()

        log_audit(request.user, 'CSV_SBOM_REJECTED',
                  upload_id=upload_id,
                  product_name=upload.product_name,
                  reason=reason)

        return JsonResponse({'status': 'rejected'})

    except Exception as e:
        logger.error(f'[api_reject_sbom] Erro: {e}')
        return JsonResponse({'error': str(e)}, status=500)