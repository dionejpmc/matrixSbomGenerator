"""
apps/sbom/views.py — Views (API JSON) do app SBOM do Matrix.

────────────────────────────────────────────────────────────────────────────
CONTEÚDO DESTE ARQUIVO
────────────────────────────────────────────────────────────────────────────
Reúne os endpoints de API (retornam JSON) que sustentam o dashboard de SBOM:
consulta de componentes, grafo de dependências/vulnerabilidades no Neo4j,
gestão de VEX, upload de SBOM, métricas e comparação entre uploads.

VEX (Vulnerability Exploitability eXchange)
  • api_vex_get(vulnerability_id)        — retorna o VEX mais recente de uma vuln.
  • api_vex_declare(vulnerability_id)    — cria/atualiza um statement VEX [operador].
  • api_vex_export(product_id)           — exporta CycloneDX 1.5 + VEX (alinhado ao CRA).

Upload / ciclo de vida do SBOM
  • upload_sbom_view()                   — recebe upload de SBOM .json [operador].
  • api_deactivate_product(product_id)   — desativa um produto [administrador].
  • api_download_cyclonedx(product_id)   — baixa o CycloneDX consolidado do produto.
  • api_scan_status(product_id)          — status do pipeline de scan (polling do front).

Componentes e vulnerabilidades
  • api_components(product_id)           — lista componentes do produto (+ status VEX).
  • api_cve_detail(cve_id)               — detalhe de uma CVE e componentes afetados.
  • api_vulns_no_vex()                   — vulnerabilidades sem declaração VEX (paginado).
  • api_vulns_critical_exploit()         — vulns críticas com exploit conhecido.
  • api_component_products()             — produtos que contêm um componente (name+version).

Grafo (Neo4j)
  • api_product_graph(product_id)        — grafo do produto para o Cytoscape. Modos:
        - padrão            → produto + TODOS os componentes + CVEs + DEPENDS_ON;
        - ?severity=/?cve=  → foca nos componentes que casam o filtro de vulnerabilidade;
        - ?raw=true         → modo estrutural: só componentes + dependências, SEM CVE
                              (mais leve; ideal para firmware sem vulnerabilidades).

Métricas e comparação
  • api_bu_stats()                       — métricas por Business Unit (cards do dashboard).
  • api_diff_uploads(product_id)         — lista uploads comparáveis de um produto.
  • api_sbom_diff()                      — diff entre dois uploads (componentes/vulns).

DEPENDÊNCIAS EXTERNAS
  • PostgreSQL  — modelos SbomUpload, Component, Vulnerability, VexStatement, Product.
  • Neo4j       — grafo (Product)-[:HAS_COMPONENT]->(Component)-[:DEPENDS_ON]->(...) e
                  (Component)-[:HAS_VULNERABILITY]->(CVE). Conexão via NEO4J_URI (env).
  • MongoDB     — auditoria (log_audit / log_error) em core.mongo.
  • Celery      — process_sbom_task dispara o pipeline de vulnerabilidade.

NOTA sobre Neo4j: a conexão usa NEO4J_URI do ambiente (bolt://neo4j:7687). Não
cravar host na mão nas views — versões antigas usavam "matrix-graph", host que
não existe mais e fazia o grafo retornar vazio.
────────────────────────────────────────────────────────────────────────────
"""

import os
import hashlib
import traceback
import json
import uuid
from django.utils import timezone
import logging
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from .models import SbomUpload, Component, Vulnerability
from apps.organizations.models import Product, UserBUMembership
from tasks.sbom_tasks import process_sbom_task
from neo4j import GraphDatabase
from apps.accounts.permissions import administrador_required, operador_required
from core.mongo import log_audit, log_error
from .models import VexStatement



UPLOAD_DIR = "/data/uploads"
NEO4J_URI      = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER_VAR = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "outra_senha_forte_aqui")

logger = logging.getLogger(__name__)


def _neo4j_driver():
    """Cria um driver Neo4j a partir das credenciais do ambiente.
    Ponto único de conexão — todas as views que falam com o grafo usam este
    helper, em vez de reler as envs ou (pior) cravar o host na mão."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER_VAR, NEO4J_PASSWORD))

 
@login_required
def api_vex_get(request, vulnerability_id):
    """Retorna o VEX statement atual de uma vulnerabilidade."""
    vuln = Vulnerability.objects.filter(id=vulnerability_id).first()
    if not vuln:
        return JsonResponse({'error': 'Vulnerabilidade não encontrada'}, status=404)
 
    statement = VexStatement.objects.filter(vulnerability=vuln).order_by('-statement_time_last_updated').first()
 
    if not statement:
        return JsonResponse({'has_vex': False, 'status': 'under_investigation'})
 
    return JsonResponse({
        'has_vex': True,
        'id': str(statement.id),
        'status': statement.status,
        'justification': statement.justification or '',
        'impact_statement': statement.impact_statement or '',
        'action_statement': statement.action_statement or '',
        'status_notes': statement.status_notes or '',
        'author': statement.author.username if statement.author else '—',
        'statement_version': statement.statement_version,
        'doc_version': statement.doc_version,
        'first_issued': statement.statement_time_first_issued.isoformat(),
        'last_updated': statement.statement_time_last_updated.isoformat(),
    })
 
 
@login_required
@operador_required
@require_http_methods(['POST'])
def api_vex_declare(request, vulnerability_id):
    """
    Cria ou atualiza um VEX statement para uma vulnerabilidade.
 
    Body:
    {
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "impact_statement": "O produto usa log4j mas não expõe JNDI lookup",
        "action_statement": "",
        "status_notes": ""
    }
 
    Regras CISA:
    - affected → action_statement obrigatório
    - not_affected → justification OU impact_statement obrigatório
    """
    vuln = Vulnerability.objects.filter(id=vulnerability_id).select_related('component__product').first()
    if not vuln:
        return JsonResponse({'error': 'Vulnerabilidade não encontrada'}, status=404)
 
    data = json.loads(request.body)
    status = data.get('status', '').strip()
    justification = data.get('justification', '').strip() or None
    impact_statement = data.get('impact_statement', '').strip() or None
    action_statement = data.get('action_statement', '').strip() or None
    status_notes = data.get('status_notes', '').strip() or None
 
    # CISA validation rules
    valid_statuses = ['under_investigation', 'affected', 'not_affected', 'fixed']
    if status not in valid_statuses:
        return JsonResponse({'error': f'Status inválido. Use: {", ".join(valid_statuses)}'}, status=400)
 
    if status == 'affected' and not action_statement:
        return JsonResponse({
            'error': 'action_statement é obrigatório quando status é "affected" (CISA VEX requirement)'
        }, status=400)
 
    if status == 'not_affected' and not justification and not impact_statement:
        return JsonResponse({
            'error': 'justification ou impact_statement é obrigatório quando status é "not_affected" (CISA VEX requirement)'
        }, status=400)
 
    # Create or update
    statement, created = VexStatement.objects.get_or_create(
        vulnerability=vuln,
        defaults={
            'author': request.user,
            'status': status,
            'justification': justification,
            'impact_statement': impact_statement,
            'action_statement': action_statement,
            'status_notes': status_notes,
        }
    )
 
    if not created:
        statement.status = status
        statement.justification = justification
        statement.impact_statement = impact_statement
        statement.action_statement = action_statement
        statement.status_notes = status_notes
        statement.author = request.user
        statement.save()
 
    log_audit(request.user, 'VEX_DECLARE',
              vulnerability_id=vulnerability_id,
              cve_id=vuln.cve_id,
              product=vuln.component.product.name,
              component=vuln.component.name,
              vex_status=status,
              justification=justification,
              created=created)
 
    return JsonResponse({
        'id': str(statement.id),
        'status': statement.status,
        'statement_version': statement.statement_version,
        'doc_version': statement.doc_version,
        'created': created,
    }, status=201 if created else 200)
 
 
@login_required
def api_vex_export(request, product_id):
    """
    Exporta relatório CycloneDX 1.5 completo — alinhado com CRA (Cyber Resilience Act).

    Campos CRA incluídos:
    - Identificação única do produto (name, version, purl)
    - Fornecedor/supplier
    - Licenças dos componentes
    - Hashes SHA-256 dos componentes (quando disponível via purl)
    - Todas as CVEs conhecidas com CVSS, EPSS, KEV
    - VEX statements (CISA compliant)
    - Score de risco por CVE e geral
    - Rastreabilidade (quem exportou, quando)
    """
    import json as json_lib
    import hashlib

    product = Product.objects.filter(id=product_id, active=True).first()
    if not product:
        return JsonResponse({'error': 'Produto não encontrado'}, status=404)

    components = Component.objects.filter(product=product).prefetch_related(
        'vulnerabilities__vex_statements'
    )

    if not components.exists():
        return JsonResponse({'error': 'Nenhum componente encontrado para este produto'}, status=404)

    # Map of most recent VEX statements by vulnerability_id
    vex_map = {}
    for comp in components:
        for vuln in comp.vulnerabilities.all():
            latest_vex = vuln.vex_statements.order_by('-statement_time_last_updated').first()
            if latest_vex:
                vex_map[vuln.id] = latest_vex

    # ── Componentes CRA-compliant ────────────────────────────
    components_list = []
    for comp in components:
        purl = comp.purl or f'pkg:generic/{comp.name}@{comp.version}'

        entry = {
            'type': comp.type or 'library',
            'name': comp.name,
            'version': comp.version,
            'purl': purl,
        }

        # License — required by CRA
        if comp.license:
            entry['licenses'] = [{'license': {'id': comp.license}}]
        else:
            entry['licenses'] = [{'license': {'name': 'NOASSERTION'}}]

        # CPE — important for NVD/CRA correlation
        if hasattr(comp, 'cpe') and comp.cpe:
            entry['cpe'] = comp.cpe

        # Supplier — required by CRA; inferred from purl when possible (pkg:github/org/repo → org)
        supplier = 'NOASSERTION'
        if purl and 'pkg:github/' in purl:
            try:
                supplier = purl.split('pkg:github/')[1].split('/')[0]
            except Exception:
                pass
        elif purl and 'pkg:deb/' in purl:
            try:
                supplier = purl.split('pkg:deb/')[1].split('/')[0]
            except Exception:
                pass
        entry['supplier'] = {'name': supplier}

        # Stable SHA-256 derived from name@version (real binary hash not available without the file)
        stable_id = hashlib.sha256(f"{comp.name}@{comp.version}".encode()).hexdigest()
        entry['hashes'] = [{'alg': 'SHA-256', 'content': stable_id}]

        components_list.append(entry)

    # ── Vulnerabilidades ─────────────────────────────────────
    vulnerabilities = []
    total_risk = 0.0
    critical_count = 0
    high_count = 0

    for comp in components:
        for vuln in comp.vulnerabilities.all():
            risk_score = round(
                (vuln.cvss_score or 0) *
                (vuln.epss_score or 0) *
                (2.0 if vuln.known_exploited else 1.0) *
                (1.5 if vuln.known_ransomware else 1.0),
                4
            )
            total_risk += risk_score

            if vuln.severity == 'CRITICAL':
                critical_count += 1
            elif vuln.severity == 'HIGH':
                high_count += 1

            vex = vex_map.get(vuln.id)
            purl = comp.purl or f'pkg:generic/{comp.name}@{comp.version}'

            entry = {
                'id': vuln.cve_id,
                'source': {
                    'name': 'NVD',
                    'url': f'https://nvd.nist.gov/vuln/detail/{vuln.cve_id}',
                },
                'ratings': [
                    {
                        'source': {'name': 'NVD'},
                        'score': vuln.cvss_score,
                        'severity': vuln.severity.lower(),
                        'method': 'CVSSv3',
                    }
                ],
                'cwes': [],
                'description': vuln.description or '',
                'recommendation': 'Update to a patched version when available.',
                'properties': [
                    *([{'name': 'matrix:epss_score', 'value': str(vuln.epss_score)}] if vuln.epss_score is not None else []),
                    {'name': 'matrix:known_exploited',  'value': str(vuln.known_exploited)},
                    {'name': 'matrix:known_ransomware', 'value': str(vuln.known_ransomware)},
                    {'name': 'matrix:risk_score',       'value': str(risk_score)},
                ],
                'affects': [
                    {
                        'ref': purl,
                        'versions': [{'version': comp.version, 'status': 'affected'}],
                    }
                ],
                'analysis': {
                    'state': vex.status if vex else 'in_triage',
                    'justification': vex.justification or '' if vex else '',
                    'detail': (vex.action_statement or vex.impact_statement or '') if vex else '',
                    'response': [],
                    'firstIssued': vex.statement_time_first_issued.isoformat() if vex else None,
                    'lastUpdated': vex.statement_time_last_updated.isoformat() if vex else None,
                },
            }
            vulnerabilities.append(entry)

    # ── Overall risk level ───────────────────────────────────
    if total_risk >= 50:
        risk_level = 'CRITICAL'
    elif total_risk >= 20:
        risk_level = 'HIGH'
    elif total_risk >= 5:
        risk_level = 'MEDIUM'
    elif total_risk > 0:
        risk_level = 'LOW'
    else:
        risk_level = 'MINIMAL'

    # ── Fetch the original SBOM for its hash ─────────────────
    sbom_upload = SbomUpload.objects.filter(
        product=product, status='COMPLETED'
    ).order_by('-uploaded_at').first()

    # ── Documento CycloneDX 1.5 CRA-compliant ───────────────
    doc = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'version': 1,
        'serialNumber': f'urn:uuid:{str(uuid.uuid4())}',
        'metadata': {
            'timestamp': timezone.now().isoformat(),
            'lifecycles': [{'phase': 'operations'}],
            'tools': [
                {
                    'vendor': 'Matrix Security',
                    'name': 'Matrix SBOM Monitor',
                    'version': '1.0',
                }
            ],
            'authors': [
                {
                    'name': request.user.get_full_name() or request.user.username,
                    'email': request.user.email or '',
                }
            ],
            'manufacture': {
                'name': product.business_unit.name if product.business_unit else 'NOASSERTION',
            },
            'supplier': {
                'name': product.business_unit.name if product.business_unit else 'NOASSERTION',
            },
            'component': {
                'type': 'firmware',
                'name': product.name,
                'version': product.version or '',
                'supplier': {
                    'name': product.business_unit.name if product.business_unit else 'NOASSERTION',
                },
                'hashes': [
                    {'alg': 'SHA-256', 'content': sbom_upload.hashcode}
                ] if sbom_upload and sbom_upload.hashcode else [],
            },
            'properties': [
                {'name': 'cra:compliance_standard',  'value': 'EU Cyber Resilience Act 2024/2847'},
                {'name': 'cra:sbom_type',            'value': 'VEX'},
                {'name': 'cra:sbom_format',          'value': 'CycloneDX 1.5'},
                {'name': 'matrix:risk_score',        'value': str(round(total_risk, 2))},
                {'name': 'matrix:risk_level',        'value': risk_level},
                {'name': 'matrix:total_vulns',       'value': str(len(vulnerabilities))},
                {'name': 'matrix:critical_count',    'value': str(critical_count)},
                {'name': 'matrix:high_count',        'value': str(high_count)},
                {'name': 'matrix:vex_count',         'value': str(len(vex_map))},
                {'name': 'matrix:exported_by',       'value': request.user.username},
                {'name': 'matrix:exported_at',       'value': timezone.now().isoformat()},
            ],
        },
        'components': components_list,
        'vulnerabilities': vulnerabilities,
    }

    safe_name = "".join(c for c in product.name if c.isalnum() or c in '-_')
    filename = f"matrix-cra-vex-{safe_name}-{timezone.now().strftime('%Y%m%d')}.json"

    response = HttpResponse(
        json_lib.dumps(doc, indent=2, ensure_ascii=False),
        content_type='application/json',
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    log_audit(request.user, 'VEX_EXPORT_CRA',
              product_id=product_id,
              product_name=product.name,
              total_vulns=len(vulnerabilities),
              vex_count=len(vex_map),
              risk_score=round(total_risk, 2),
              risk_level=risk_level)

    return response

@login_required
@operador_required
def upload_sbom_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Método não permitido'}, status=405)

    chunk = request.FILES.get('file') or request.FILES.get('sbom_file')
    upload_id = request.POST.get('upload_id')
    chunk_index = int(request.POST.get('chunk_index', 0))
    total_chunks = int(request.POST.get('total_chunks', 1))
    filename = request.POST.get('filename', 'upload')
    product_name = request.POST.get('product_name', '').strip()
    product_version = request.POST.get('product_version', '').strip()

    # Valida nome e versão no primeiro chunk — antes de salvar qualquer coisa
    if chunk_index == 0:
        if not product_name:
            return JsonResponse({'error': 'Nome do produto é obrigatório.'}, status=400)
        if not product_version:
            return JsonResponse({'error': 'Versão do produto é obrigatória.'}, status=400)

    tmp_dir = os.path.join(UPLOAD_DIR, upload_id)
    os.makedirs(tmp_dir, exist_ok=True)
    chunk_path = os.path.join(tmp_dir, f'chunk_{chunk_index:05d}')

    with open(chunk_path, 'wb') as f:
        for part in chunk.chunks():
            f.write(part)

    if chunk_index + 1 < total_chunks:
        return JsonResponse({'status': 'chunk_ok', 'chunk': chunk_index, 'total': total_chunks})

    final_filename = f'{upload_id}_{filename}'
    final_path = os.path.join(UPLOAD_DIR, final_filename)

    try:
        with open(final_path, 'wb') as final_file:
            for i in range(total_chunks):
                part_path = os.path.join(tmp_dir, f'chunk_{i:05d}')
                with open(part_path, 'rb') as part:
                    final_file.write(part.read())
                os.remove(part_path)
        os.rmdir(tmp_dir)

        from django.core.files import File

        import logging; logging.getLogger("django").warning(f"UPLOAD REQUEST user={request.user.username} bu={UserBUMembership.objects.filter(user=request.user).first()}");
        membership = UserBUMembership.objects.filter(user=request.user).first()
        user_bu = membership.business_unit if membership else None

        # Compute hash before creating any record
        sha256 = hashlib.sha256()
        with open(final_path, 'rb') as f:
            for block in iter(lambda: f.read(8192), b''):
                sha256.update(block)
        file_hash = sha256.hexdigest()

        # Reject if an identical SBOM is already active or being processed,
        # but only when its linked product is still active.
        existing = SbomUpload.objects.filter(
            hashcode=file_hash,
            status__in=['COMPLETED', 'PENDING', 'PROCESSING'],
            product__active=True
        ).first()

        if existing:
            if os.path.exists(final_path):
                os.remove(final_path)
            return JsonResponse({
                'status': 'duplicate',
                'message': 'Este SBOM já está ativo ou sendo processado para um produto ativo.',
                'existing_id': str(existing.id),
            }, status=200)
        
        product_obj, created = Product.objects.update_or_create(
            name=product_name,
            business_unit=user_bu,
            defaults={
                'version': product_version,
                'created_by': request.user,
                'active': True,
            }
        )

        with open(final_path, 'rb') as f:
            upload_record = SbomUpload.objects.create(
                product_name=product_name,
                product=product_obj,
                status='PENDING'
            )
            upload_record.sbom_file.save(filename, File(f), save=True)

        os.remove(final_path)

        process_sbom_task.delay(str(upload_record.id))

        log_audit(request.user, 'UPLOAD_SBOM',
                  upload_id=str(upload_record.id),
                  product_name=product_name,
                  product_version=product_version,
                  filename=filename,
                  ip=request.META.get('REMOTE_ADDR'))

        return JsonResponse({
            'status': 'success',
            'message': f'Produto {product_obj.name} v{product_obj.version} processando!',
            'id': str(upload_record.id),
        }, status=201)

    except Exception as e:
        print(traceback.format_exc())
        log_error('upload_sbom_view', str(e),
                  user=request.user.username,
                  product_name=product_name,
                  ip=request.META.get('REMOTE_ADDR'))
        if os.path.exists(final_path):
            os.remove(final_path)
        return JsonResponse({'error': f'Erro interno: {str(e)}'}, status=500)


@login_required
@require_http_methods(['POST'])
@administrador_required
def api_deactivate_product(request, product_id):
    # Deactivates a product — renames it to avoid uniqueness conflicts on future uploads.
    membership = UserBUMembership.objects.filter(user=request.user).first()
    if not membership:
        return JsonResponse({'error': 'Acesso negado'}, status=403)

    product = Product.objects.filter(
        id=product_id,
        business_unit=membership.business_unit
    ).first()

    if not product:
        return JsonResponse({'error': 'Produto não encontrado'}, status=404)

    original_name = product.name
    product.active = False
    product.name = f"inactivated_{product.id}_{product.name}"
    product.save()

    # Mark as inactive in Neo4j as well
    try:
        driver = _neo4j_driver()
        with driver.session() as session:
            session.run("""
                MATCH (p:Product {db_id: toInteger($product_id)})
                SET p.active = false,
                    p.name = $new_name
            """, {
                "product_id": product_id,
                "new_name": product.name,
            })
        driver.close()
    except Exception as e:
        logger.warning(f"[api_deactivate_product] Neo4j não atualizado: {e}")

    log_audit(request.user, 'DEACTIVATE_PRODUCT',
              product_id=product_id,
              product_name=original_name,
              ip=request.META.get('REMOTE_ADDR'))

    return JsonResponse({
        'status': 'deactivated',
        'product': original_name
    })

@login_required
def api_cve_detail(request, cve_id):
    vuln = Vulnerability.objects.filter(cve_id=cve_id).first()
    if not vuln:
        return JsonResponse({'error': 'não encontrado'}, status=404)

    products_affected = Component.objects.filter(
        name=vuln.component.name,
        version=vuln.component.version
    ).values('product').distinct().count()

    transitive = []
    try:
        driver = _neo4j_driver()
        with driver.session() as session:
            result = session.run("""
                MATCH (a:Component)-[:DEPENDS_ON*1..]->(b:Component)-[:HAS_VULNERABILITY]->(v:CVE {cveId: $cve_id})
                WITH DISTINCT a, b
                RETURN a.name as dependent, a.version as dep_version,
                       b.name as vulnerable, b.version as vuln_version
                ORDER BY dependent
            """, {"cve_id": cve_id})
            transitive = [dict(r) for r in result]
        driver.close()
    except Exception as e:
        print(f"Neo4j error: {e}")

    return JsonResponse({
        'cve_id': vuln.cve_id,
        'severity': vuln.severity,
        'description': vuln.description,
        'cvss_score': vuln.cvss_score,
        'status': vuln.status,
        'component': vuln.component.name,
        'component_version': vuln.component.version,
        'transitive_impact': transitive,
        'products_affected': products_affected,
    })


@login_required
def api_product_graph(request, product_id):
    """Monta o grafo do produto para o Cytoscape (nós + arestas).

    Modos (via query string):
      • padrão            → produto + TODOS os componentes + CVEs + DEPENDS_ON.
      • ?severity=/?cve=  → foca nos componentes que casam o filtro de vuln.
      • ?raw=true         → só componentes + dependências, SEM CVE (mais leve).
    """
    import uuid as uuid_module

    severity_filter = request.GET.getlist('severity')
    cve_filter = request.GET.get('cve', '').strip().upper()
    raw_mode = request.GET.get('raw', 'false') == 'true'

    try:
        driver = _neo4j_driver()
        nodes = []
        edges = []
        seen_nodes = set()
        seen_edges = set()

        with driver.session() as session:
            vuln_filter_clause = ""
            params = {"id": str(product_id)}

            if cve_filter:
                vuln_filter_clause = "AND v.cveId CONTAINS $cve"
                params["cve"] = cve_filter
            elif severity_filter:
                vuln_filter_clause = "AND v.severity IN $severities"
                params["severities"] = [s.upper() for s in severity_filter]

            has_vuln_filter = bool(cve_filter or severity_filter)

            if raw_mode:
                # Modo estrutural: só componentes, sem tocar em vulnerabilidades.
                # Mais leve — não executa o MATCH de CVE.
                query = """
                MATCH (p:Product)
                WHERE p.db_id = toInteger($id) OR p.name = $id
                OPTIONAL MATCH (p)-[:HAS_COMPONENT]->(c:Component)
                RETURN
                    elementId(p) as prod_id, p.name as prod_name,
                    elementId(c) as comp_id, c.name as comp_name, c.version as comp_version,
                    null as vuln_id, null as vuln_cve, null as vuln_severity
                """
            elif has_vuln_filter:
                # Com filtro de vuln: foca nos componentes que têm CVE casando.
                query = f"""
                MATCH (p:Product)
                WHERE p.db_id = toInteger($id) OR p.name = $id
                MATCH (p)-[:HAS_COMPONENT]->(c:Component)-[:HAS_VULNERABILITY]->(v:CVE)
                WHERE true {vuln_filter_clause}
                RETURN
                    elementId(p) as prod_id, p.name as prod_name,
                    elementId(c) as comp_id, c.name as comp_name, c.version as comp_version,
                    elementId(v) as vuln_id, v.cveId as vuln_cve, v.severity as vuln_severity
                """
            else:
                # Sem filtro: TODOS os componentes (mesmo sem CVE) + suas CVEs.
                query = """
                MATCH (p:Product)
                WHERE p.db_id = toInteger($id) OR p.name = $id
                OPTIONAL MATCH (p)-[:HAS_COMPONENT]->(c:Component)
                OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:CVE)
                RETURN
                    elementId(p) as prod_id, p.name as prod_name,
                    elementId(c) as comp_id, c.name as comp_name, c.version as comp_version,
                    elementId(v) as vuln_id, v.cveId as vuln_cve, v.severity as vuln_severity
                """

            records = list(session.run(query, **params))

            # Relações de dependência entre componentes (DEPENDS_ON) do produto.
            dep_records = list(session.run("""
                MATCH (p:Product)-[:HAS_COMPONENT]->(a:Component)-[:DEPENDS_ON]->(b:Component)
                WHERE p.db_id = toInteger($id) OR p.name = $id
                RETURN elementId(a) as src_id, elementId(b) as tgt_id
            """, id=str(product_id)))

        driver.close()

        if not records:
            return JsonResponse({"nodes": [], "edges": []})

        for record in records:
            prod_id = record["prod_id"]
            comp_id = record["comp_id"]
            vuln_id = record["vuln_id"]

            if prod_id and prod_id not in seen_nodes:
                nodes.append({"data": {"id": prod_id, "label": record["prod_name"] or "Produto", "type": "product"}})
                seen_nodes.add(prod_id)

            if comp_id and comp_id not in seen_nodes:
                label = record["comp_name"] or "Component"
                if record["comp_version"]:
                    label += f"\n{record['comp_version']}"
                nodes.append({"data": {"id": comp_id, "label": label, "type": "component"}})
                seen_nodes.add(comp_id)

            if prod_id and comp_id:
                edge_key = (prod_id, comp_id)
                if edge_key not in seen_edges:
                    edges.append({"data": {"id": str(uuid_module.uuid4()), "source": prod_id, "target": comp_id, "label": "HAS_COMPONENT"}})
                    seen_edges.add(edge_key)

            if vuln_id and vuln_id not in seen_nodes:
                nodes.append({"data": {"id": vuln_id, "label": record["vuln_cve"] or "CVE", "type": "cve", "severity": record["vuln_severity"] or "UNKNOWN"}})
                seen_nodes.add(vuln_id)

            if comp_id and vuln_id:
                edge_key = (comp_id, vuln_id)
                if edge_key not in seen_edges:
                    edges.append({"data": {"id": str(uuid_module.uuid4()), "source": comp_id, "target": vuln_id, "label": "HAS_VULNERABILITY"}})
                    seen_edges.add(edge_key)

        # Arestas de dependência entre componentes (DEPENDS_ON). Só liga nós que
        # já entraram no grafo (componentes deste produto).
        for dep in dep_records:
            src_id, tgt_id = dep["src_id"], dep["tgt_id"]
            if src_id in seen_nodes and tgt_id in seen_nodes:
                edge_key = (src_id, tgt_id, "DEPENDS_ON")
                if edge_key not in seen_edges:
                    edges.append({"data": {"id": str(uuid_module.uuid4()), "source": src_id, "target": tgt_id, "label": "DEPENDS_ON"}})
                    seen_edges.add(edge_key)

        return JsonResponse({"nodes": nodes, "edges": edges})

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)


@login_required
def api_components(request, product_id):
    components = Component.objects.filter(product_id=product_id).prefetch_related('vulnerabilities')

    # Avoid N+1 queries — fetch the most recent VEX status for all vulnerabilities in a single query
    from django.db.models import Max
    vuln_ids = Vulnerability.objects.filter(
        component__product_id=product_id
    ).values_list('id', flat=True)

    # Build dictionary {vulnerability_id: vex_status}
    vex_map = {}
    latest_vex = (
        VexStatement.objects
        .filter(vulnerability_id__in=vuln_ids)
        .order_by('vulnerability_id', '-statement_time_last_updated')
        .distinct('vulnerability_id')
        .values('vulnerability_id', 'status')
    )
    for row in latest_vex:
        vex_map[row['vulnerability_id']] = row['status']

    result = []
    for comp in components:
        result.append({
            'id': comp.id,
            'name': comp.name,
            'version': comp.version,
            'type': comp.type,
            'purl': comp.purl,
            'license': comp.license,
            'vulnerabilities': [
                {
                    'id': v.id,
                    'cve_id': v.cve_id,
                    'severity': v.severity,
                    'description': v.description,
                    'cvss_score': v.cvss_score,
                    'epss_score': v.epss_score,
                    'known_exploited': v.known_exploited,
                    'known_ransomware': v.known_ransomware,
                    'status': v.status,
                    'vex_status': vex_map.get(v.id),
                }
                for v in comp.vulnerabilities.all()
            ],
            'vuln_count': comp.vulnerabilities.count(),
        })

    return JsonResponse({'components': result})


@login_required
def api_bu_stats(request):
    membership = UserBUMembership.objects.filter(user=request.user).first()
    if not membership:
        return JsonResponse({'sboms': 0, 'total_vulns': 0, 'resolved_vulns': 0,
                            'critical_exploit': 0, 'no_vex': 0,
                            'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}})

    user_bu = membership.business_unit

    sboms = Product.objects.filter(
        business_unit=user_bu,
        active=True,
        uploads__status='COMPLETED',
    ).distinct().count()

    vulns = Vulnerability.objects.filter(
        component__product__business_unit=user_bu,
        component__product__active=True,
    )

    # CVEs críticos com exploit conhecido
    critical_exploit = vulns.filter(
        severity='CRITICAL',
        known_exploited=True,
    ).count()

    # Vulnerabilidades sem declaração VEX
    from apps.sbom.models import VexStatement
    vulns_with_vex = VexStatement.objects.filter(
        vulnerability__component__product__business_unit=user_bu,
        vulnerability__component__product__active=True,
    ).values_list('vulnerability_id', flat=True).distinct()

    no_vex = vulns.exclude(id__in=vulns_with_vex).count()

    # Distribuição por severidade
    from django.db.models import Count
    severity_counts = vulns.values('severity').annotate(total=Count('id'))
    by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
    for item in severity_counts:
        sev = item['severity'].upper()
        if sev in by_severity:
            by_severity[sev] = item['total']

    return JsonResponse({
        'sboms': sboms,
        'total_vulns': vulns.count(),
        'resolved_vulns': vulns.filter(status__in=['RESOLVED', 'ACCEPTED']).count(),
        'critical_exploit': critical_exploit,
        'no_vex': no_vex,
        'by_severity': by_severity,
    })


@login_required
def api_vulns_no_vex(request):
    """Lista vulnerabilidades sem VEX declaration — paginada, com filtro por severidade."""
    membership = UserBUMembership.objects.filter(user=request.user).first()
    if not membership:
        return JsonResponse({'vulns': [], 'total': 0})

    user_bu = membership.business_unit
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 20))
    severity_filter = request.GET.get('severity', '')  # ex: CRITICAL,HIGH

    from apps.sbom.models import VexStatement
    from django.db.models import Case, When, Value, IntegerField

    vulns_with_vex = VexStatement.objects.filter(
        vulnerability__component__product__business_unit=user_bu,
    ).values_list('vulnerability_id', flat=True).distinct()

    vulns = Vulnerability.objects.filter(
        component__product__business_unit=user_bu,
        component__product__active=True,
    ).exclude(id__in=vulns_with_vex).select_related('component', 'component__product')

    # Filtro por severidade
    if severity_filter:
        severities = [s.strip().upper() for s in severity_filter.split(',') if s.strip()]
        if severities:
            vulns = vulns.filter(severity__in=severities)

    # Ordena por severidade (CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN) e CVSS desc
    vulns = vulns.annotate(
        sev_order=Case(
            When(severity='CRITICAL', then=Value(0)),
            When(severity='HIGH',     then=Value(1)),
            When(severity='MEDIUM',   then=Value(2)),
            When(severity='LOW',      then=Value(3)),
            default=Value(4),
            output_field=IntegerField(),
        )
    ).order_by('sev_order', '-cvss_score')

    total = vulns.count()
    start = (page - 1) * page_size
    vulns_page = vulns[start:start + page_size]

    result = [{
        'id': v.id,
        'cve_id': v.cve_id,
        'severity': v.severity,
        'cvss_score': v.cvss_score,
        'epss_score': v.epss_score,
        'known_exploited': v.known_exploited,
        'component': v.component.name,
        'component_version': v.component.version,
        'product': v.component.product.name,
    } for v in vulns_page]

    return JsonResponse({'vulns': result, 'total': total, 'page': page, 'page_size': page_size})


@login_required
def api_vulns_critical_exploit(request):
    """Lista CVEs críticos com exploit conhecido — paginada."""
    membership = UserBUMembership.objects.filter(user=request.user).first()
    if not membership:
        return JsonResponse({'vulns': [], 'total': 0})

    user_bu = membership.business_unit
    page = int(request.GET.get('page', 1))
    page_size = int(request.GET.get('page_size', 20))

    vulns = Vulnerability.objects.filter(
        component__product__business_unit=user_bu,
        component__product__active=True,
        severity='CRITICAL',
        known_exploited=True,
    ).select_related('component', 'component__product').order_by('-cvss_score', '-epss_score')

    total = vulns.count()
    start = (page - 1) * page_size
    vulns_page = vulns[start:start + page_size]

    result = [{
        'id': v.id,
        'cve_id': v.cve_id,
        'severity': v.severity,
        'cvss_score': v.cvss_score,
        'epss_score': v.epss_score,
        'known_ransomware': v.known_ransomware,
        'component': v.component.name,
        'component_version': v.component.version,
        'product': v.component.product.name,
    } for v in vulns_page]

    return JsonResponse({'vulns': result, 'total': total, 'page': page, 'page_size': page_size})


@login_required
def api_component_products(request):
    name = request.GET.get('name', '')
    version = request.GET.get('version', '')
    count = Component.objects.filter(
        name=name,
        version=version,
        product__active=True
    ).values('product').distinct().count()
    return JsonResponse({'count': count})



@login_required
def api_download_cyclonedx(request, product_id):
    from django.http import FileResponse
    from django.conf import settings

    membership = UserBUMembership.objects.filter(user=request.user).first()
    if not membership:
        return JsonResponse({'error': 'Acesso negado'}, status=403)

    user_bu = membership.business_unit

    try:
        upload = SbomUpload.objects.filter(
            product_id=product_id,
            product__business_unit=user_bu,
            status='COMPLETED'
        ).latest('uploaded_at')
    except SbomUpload.DoesNotExist:
        return JsonResponse({'error': 'SBOM não encontrado'}, status=404)

    sbom_relative = upload.sbom_file.name
    sbom_path = os.path.realpath(
        os.path.join(settings.MEDIA_ROOT, sbom_relative)
    )
    media_root = os.path.realpath(settings.MEDIA_ROOT)

    if not sbom_path.startswith(media_root):
        return JsonResponse({'error': 'Acesso negado'}, status=403)

    if not os.path.exists(sbom_path):
        return JsonResponse({'error': 'Arquivo não encontrado'}, status=404)

    if not sbom_path.endswith('.json'):
        return JsonResponse({'error': 'Formato inválido'}, status=400)

    safe_name = "".join(
        c for c in upload.product_name if c.isalnum() or c in '-_'
    )
    filename = f"sbom-{safe_name}-cyclonedx.json"

    log_audit(request.user, 'DOWNLOAD_CYCLONEDX',
              product_id=product_id,
              filename=filename,
              ip=request.META.get('REMOTE_ADDR'))

    return FileResponse(
        open(sbom_path, 'rb'),
        content_type='application/json',
        as_attachment=True,
        filename=filename
    )



@login_required
def api_scan_status(request, product_id):
    """
    Retorna o status atual do SBOM de um produto.
    Usado pelo polling do dashboard para atualizar badges em tempo real.
    """
    from apps.organizations.models import UserBUMembership

    # Verifica acesso
    if not request.user.is_superuser:
        membership = UserBUMembership.objects.filter(user=request.user).first()
        if not membership:
            return JsonResponse({'error': 'Acesso negado'}, status=403)
        upload = SbomUpload.objects.filter(
            product_id=product_id,
            product__business_unit=membership.business_unit,
        ).order_by('-uploaded_at').first()
    else:
        upload = SbomUpload.objects.filter(
            product_id=product_id,
        ).order_by('-uploaded_at').first()

    if not upload:
        return JsonResponse({'status': 'NONE'})

    response = {
        'status': upload.status,
        'upload_id': str(upload.id),
        'hashcode': upload.hashcode,
        'progress': None,
    }

    # Se estiver processando, tenta obter progresso da task Celery
    if upload.status in ('PENDING', 'PROCESSING'):
        try:
            from celery.result import AsyncResult
            # Busca task pelo upload_id nos metadados
            # task_id is stored when the task is dispatched
            if hasattr(upload, 'task_id') and upload.task_id:
                result = AsyncResult(upload.task_id)
                if result.state == 'PROGRESS':
                    response['progress'] = result.info
        except Exception:
            pass

    return JsonResponse(response)

@login_required
def api_diff_uploads(request, product_id):
    """
    Lista todos os SBOMs COMPLETED da BU do usuário para seleção no diff.
    O produto atual (product_id) é usado para pré-selecionar o SBOM A.
    """
    membership = UserBUMembership.objects.filter(user=request.user).first()
    user_bu = membership.business_unit if membership else None

    # SBOM A — upload mais recente do produto atual
    upload_a = SbomUpload.objects.filter(
        product__id=product_id,
        product__business_unit=user_bu,
        status='COMPLETED',
        active=True,
    ).order_by('-uploaded_at').first()

    # Todos os SBOMs da BU — para selecionar o SBOM B
    all_uploads = SbomUpload.objects.filter(
        product__business_unit=user_bu,
        status='COMPLETED',
        active=True,
    ).select_related('product').order_by('-uploaded_at')

    def make_label(u):
        name = u.product_name or (u.product.name if u.product else '—')
        version = u.product.version if u.product else ''
        date = u.uploaded_at.strftime('%d/%m/%Y %H:%M')
        label = name
        if version:
            label += f' v{version}'
        label += f' — {date}'
        return label

    return JsonResponse({
        'upload_a': str(upload_a.id) if upload_a else None,
        'uploads': [{'id': str(u.id), 'label': make_label(u)} for u in all_uploads],
    })


@login_required
def api_sbom_diff(request):
    """
    Compara dois SbomUploads lendo os arquivos CycloneDX JSON diretamente.
    Funciona para qualquer par de SBOMs — mesmo produto ou produtos diferentes.
    """
    upload_a_id = request.GET.get('a')
    upload_b_id = request.GET.get('b')

    if not upload_a_id or not upload_b_id:
        return JsonResponse({'error': 'Parâmetros a e b são obrigatórios'}, status=400)

    if upload_a_id == upload_b_id:
        return JsonResponse({'error': 'Selecione SBOMs diferentes'}, status=400)

    membership = UserBUMembership.objects.filter(user=request.user).first()
    user_bu = membership.business_unit if membership else None

    try:
        upload_a = SbomUpload.objects.get(id=upload_a_id, product__business_unit=user_bu)
        upload_b = SbomUpload.objects.get(id=upload_b_id, product__business_unit=user_bu)
    except SbomUpload.DoesNotExist:
        return JsonResponse({'error': 'SBOM não encontrado'}, status=404)

    def read_components(upload):
        """Lê componentes do arquivo CycloneDX JSON."""
        if not upload.sbom_file:
            return {}
        try:
            import json
            upload.sbom_file.open('r')
            data = json.load(upload.sbom_file)
            upload.sbom_file.close()
            comps = {}
            for c in data.get('components', []):
                name = c.get('name', '').strip()
                version = c.get('version', '').strip()
                purl = c.get('purl', '')
                ctype = c.get('type', '')
                if name:
                    comps[name.lower()] = {
                        'name': name,
                        'version': version,
                        'type': ctype,
                        'purl': purl,
                    }
            return comps
        except Exception as e:
            logger.error(f'[api_sbom_diff] Erro ao ler JSON: {e}')
            return {}

    comps_a = read_components(upload_a)
    comps_b = read_components(upload_b)

    if not comps_a and not comps_b:
        return JsonResponse({'error': 'Não foi possível ler os arquivos SBOM'}, status=500)

    names_a = set(comps_a.keys())
    names_b = set(comps_b.keys())

    added_names   = names_b - names_a
    removed_names = names_a - names_b
    common_names  = names_a & names_b

    added   = [comps_b[n] for n in sorted(added_names)]
    removed = [comps_a[n] for n in sorted(removed_names)]
    updated = []
    for n in sorted(common_names):
        ca, cb = comps_a[n], comps_b[n]
        if ca['version'] != cb['version']:
            updated.append({
                'name': ca['name'],
                'old_version': ca['version'],
                'new_version': cb['version'],
            })

    # CVEs — lidos do banco (mais preciso que o JSON)
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}

    vulns_a = {v.cve_id for v in Vulnerability.objects.filter(component__product=upload_a.product)}
    vulns_b_qs = Vulnerability.objects.filter(component__product=upload_b.product).select_related('component')
    vulns_b = {v.cve_id: v for v in vulns_b_qs}

    new_vulns = sorted([
        {'cve_id': cve_id, 'severity': v.severity, 'component': v.component.name}
        for cve_id, v in vulns_b.items() if cve_id not in vulns_a
    ], key=lambda v: sev_order.get(v['severity'], 4))

    vulns_a_qs = Vulnerability.objects.filter(component__product=upload_a.product).select_related('component')
    vulns_a_map = {v.cve_id: v for v in vulns_a_qs}

    resolved_vulns = sorted([
        {'cve_id': cve_id, 'severity': v.severity, 'component': v.component.name}
        for cve_id, v in vulns_a_map.items() if cve_id not in vulns_b
    ], key=lambda v: sev_order.get(v['severity'], 4))

    return JsonResponse({
        'sbom_a': upload_a.product_name or upload_a.product.name,
        'sbom_b': upload_b.product_name or upload_b.product.name,
        'added':          added,
        'removed':        removed,
        'updated':        updated,
        'new_vulns':      new_vulns,
        'resolved_vulns': resolved_vulns,
    })