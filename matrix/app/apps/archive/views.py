"""
apps/archive/views.py

Management of deactivated SBOMs — viewing, export and permanent deletion.
"""
import os
import logging
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, FileResponse
from django.views.decorators.http import require_http_methods
from django.db.models import Count, Q
from django.conf import settings

from apps.sbom.models import SbomUpload, Component, Vulnerability
from apps.organizations.models import Product, UserBUMembership
from apps.accounts.permissions import administrador_required, is_administrador
from core.mongo import log_audit, log_error

logger = logging.getLogger(__name__)


def _get_inactive_products(user):
    """Returns all inactive products — superuser access only."""
    return Product.objects.filter(active=False).select_related('business_unit')


# ─────────────────────────────────────────────────────────────
# PAGE VIEW
# ─────────────────────────────────────────────────────────────

@login_required
def archive_view(request):
    if not request.user.is_superuser:
        from django.contrib import messages
        messages.error(request, 'Access restricted to system administrators.')
        return __import__('django.shortcuts', fromlist=['redirect']).redirect('dashboard')
    return render(request, 'usuarios/archive.html', {
        'can_delete': True,  # superuser can always delete
    })


# ─────────────────────────────────────────────────────────────
# API: LISTA DE PRODUTOS INATIVOS
# ─────────────────────────────────────────────────────────────

@login_required
def api_archive_products(request):
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Access denied'}, status=403)
    products = _get_inactive_products(request.user).select_related(
        'business_unit'
    ).annotate(
        component_count=Count('components', distinct=True),
        vuln_count=Count('components__vulnerabilities', distinct=True),
        critical_count=Count(
            'components__vulnerabilities',
            filter=Q(components__vulnerabilities__severity='CRITICAL'),
            distinct=True
        ),
    ).order_by('-created_at')

    total_components = sum(p.component_count for p in products)
    total_vulns = sum(p.vuln_count for p in products)

    result = []
    for p in products:
        # Original name without the inactivated_ID_ prefix
        original_name = p.name
        if original_name.startswith('inactivated_'):
            parts = original_name.split('_', 2)
            if len(parts) >= 3:
                original_name = parts[2]

        # Fetch product uploads
        upload = SbomUpload.objects.filter(product=p).order_by('-uploaded_at').first()
        deactivated_at = upload.uploaded_at.strftime('%d/%m/%Y %H:%M') if upload else ''
        sbom_hash = upload.hashcode if upload else None

        # Fetch RAUC bundle hash
        rauc_hash = None
        try:
            from apps.rootfs.models import RootFS
            rootfs = RootFS.objects.filter(product=p).order_by('-id').first()
            if rootfs:
                rauc_hash = rootfs.bundle_hash
        except Exception:
            pass

        result.append({
            'id': p.id,
            'name': p.name,
            'original_name': original_name,
            'version': p.version or '',
            'business_unit': p.business_unit.name if p.business_unit else '—',
            'component_count': p.component_count,
            'vuln_count': p.vuln_count,
            'critical_count': p.critical_count,
            'deactivated_at': deactivated_at,
            'sbom_hash': sbom_hash,
            'rauc_hash': rauc_hash,
        })

    return JsonResponse({
        'products': result,
        'stats': {
            'total': len(result),
            'total_components': total_components,
            'total_vulns': total_vulns,
            'disk_usage': '—',
        }
    })


# ─────────────────────────────────────────────────────────────
# API: COMPONENTES DE UM PRODUTO INATIVO
# ─────────────────────────────────────────────────────────────

@login_required
def api_archive_components(request, product_id):
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Access denied'}, status=403)
    inactive = _get_inactive_products(request.user)
    product = inactive.filter(id=product_id).first()
    if not product:
        return JsonResponse({'error': 'Product not found'}, status=404)

    components = Component.objects.filter(product=product).prefetch_related('vulnerabilities')

    SEV_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'NEGLIGIBLE': 4, 'UNKNOWN': 5}

    result = []
    for comp in components:
        vulns = list(comp.vulnerabilities.all())
        max_sev = None
        if vulns:
            max_sev = min(vulns, key=lambda v: SEV_ORDER.get(v.severity, 9)).severity

        result.append({
            'id': comp.id,
            'name': comp.name,
            'version': comp.version or '',
            'purl': comp.purl or '',
            'type': comp.type or '',
            'vuln_count': len(vulns),
            'max_severity': max_sev,
        })

    # Sort by highest severity first
    result.sort(key=lambda c: (SEV_ORDER.get(c['max_severity'], 9), c['name']))

    return JsonResponse({'components': result})


# ─────────────────────────────────────────────────────────────
# API: EXPORTAR CYCLONEDX
# ─────────────────────────────────────────────────────────────

@login_required
def api_archive_export(request, product_id):
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Access denied'}, status=403)
    inactive = _get_inactive_products(request.user)
    product = inactive.filter(id=product_id).first()
    if not product:
        return JsonResponse({'error': 'Product not found'}, status=404)

    try:
        upload = SbomUpload.objects.filter(
            product=product,
            status='COMPLETED'
        ).latest('uploaded_at')
    except SbomUpload.DoesNotExist:
        return JsonResponse({'error': 'SBOM file not found'}, status=404)

    sbom_path = os.path.realpath(
        os.path.join(settings.MEDIA_ROOT, upload.sbom_file.name)
    )
    media_root = os.path.realpath(settings.MEDIA_ROOT)

    if not sbom_path.startswith(media_root):
        return JsonResponse({'error': 'Access denied'}, status=403)

    if not os.path.exists(sbom_path):
        return JsonResponse({'error': 'File not found on disk'}, status=404)

    # Original name for the download filename
    original_name = product.name
    if original_name.startswith('inactivated_'):
        parts = original_name.split('_', 2)
        if len(parts) >= 3:
            original_name = parts[2]

    safe_name = "".join(c for c in original_name if c.isalnum() or c in '-_')
    filename = f"archive-sbom-{safe_name}-cyclonedx.json"

    log_audit(request.user, 'ARCHIVE_EXPORT_CYCLONEDX',
              product_id=product_id,
              product_name=original_name,
              ip=request.META.get('REMOTE_ADDR'))

    return FileResponse(
        open(sbom_path, 'rb'),
        content_type='application/json',
        as_attachment=True,
        filename=filename
    )


# ─────────────────────────────────────────────────────────────
# API: DELETAR PERMANENTEMENTE
# ─────────────────────────────────────────────────────────────

@login_required
@administrador_required
@require_http_methods(['DELETE'])
def api_archive_delete(request, product_id):
    inactive = _get_inactive_products(request.user)
    product = inactive.filter(id=product_id).first()
    if not product:
        return JsonResponse({'error': 'Product not found'}, status=404)

    original_name = product.name
    if original_name.startswith('inactivated_'):
        parts = original_name.split('_', 2)
        if len(parts) >= 3:
            original_name = parts[2]

    try:
        # Delete files from disk
        for upload in SbomUpload.objects.filter(product=product):
            if upload.sbom_file and upload.sbom_file.name:
                sbom_path = os.path.join(settings.MEDIA_ROOT, upload.sbom_file.name)
                if os.path.exists(sbom_path):
                    os.remove(sbom_path)
                    logger.info(f"[archive_delete] File removed: {sbom_path}")

            # Remove Grype vulnerability results file
            vulns_path = os.path.join(settings.MEDIA_ROOT, 'vulns', f'{upload.id}.vulns.json')
            if os.path.exists(vulns_path):
                os.remove(vulns_path)

        # Remove from Neo4j — product, components and orphan CVEs
        try:
            from neo4j import GraphDatabase
            NEO4J_URI      = os.getenv("NEO4J_URI", "bolt://matrix-graph:7687")
            NEO4J_USER_VAR = os.getenv("NEO4J_USER", "neo4j")
            NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

            driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER_VAR, NEO4J_PASSWORD))
            with driver.session() as session:
                # Remove product and its HAS_COMPONENT relationships
                # CVEs that end up with no associated components are also removed
                session.run("""
                    MATCH (p:Product {db_id: toInteger($product_id)})
                    OPTIONAL MATCH (p)-[:HAS_COMPONENT]->(c:Component)
                    OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:CVE)
                    DETACH DELETE p, c
                """, {"product_id": product_id})

                # Remove orphan CVEs (no component pointing to them)
                session.run("""
                    MATCH (v:CVE)
                    WHERE NOT ()-[:HAS_VULNERABILITY]->(v)
                    DELETE v
                """)

            driver.close()
            logger.info(f"[archive_delete] Neo4j cleaned for product ID {product_id}")
        except Exception as neo_err:
            logger.warning(f"[archive_delete] Neo4j not cleaned: {neo_err}")

        # Delete the product from PostgreSQL (cascades to components, vulnerabilities, uploads)
        product.delete()

        log_audit(request.user, 'ARCHIVE_DELETE_PRODUCT',
                  product_id=product_id,
                  product_name=original_name,
                  ip=request.META.get('REMOTE_ADDR'))

        logger.info(f"[archive_delete] Product {original_name} (ID {product_id}) permanently deleted")

        return JsonResponse({'status': 'deleted', 'product': original_name})

    except Exception as e:
        logger.error(f"[archive_delete] Error deleting product {product_id}: {e}")
        log_error('archive_delete', str(e), product_id=product_id, user=request.user.username)
        return JsonResponse({'error': str(e)}, status=500)