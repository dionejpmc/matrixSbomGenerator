"""
tasks/scheduled_tasks.py

Tasks scheduled by Celery Beat:
  1. update_grype_db   — updates the Grype vulnerability database (runs before re-scan)
  2. daily_rescan_all  — re-scans all active SBOMs in sequence
"""
import subprocess
import logging
import time
from celery import shared_task, chain
from django.utils import timezone

from apps.sbom.models import SbomUpload
from core.mongo import log_task, log_error

logger = logging.getLogger(__name__)


@shared_task(name="tasks.scheduled_tasks.update_grype_db")
def update_grype_db():
    """
    Updates the Grype vulnerability database.
    Equivalent to: grype db update
    """
    logger.info("[update_grype_db] Starting Grype database update...")
    log_task('update_grype_db', 'STARTED')
    start = time.time()
    try:
        result = subprocess.run(
            ["grype", "db", "update"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        duration = round(time.time() - start, 2)
        if result.returncode == 0:
            logger.info(f"[update_grype_db] Database updated successfully.\n{result.stdout}")
            log_task('update_grype_db', 'SUCCESS',
                     duration_seconds=duration,
                     output=result.stdout.strip())
        else:
            logger.warning(f"[update_grype_db] Warning: {result.stderr}")
            log_task('update_grype_db', 'WARNING',
                     duration_seconds=duration,
                     stderr=result.stderr.strip())
    except subprocess.TimeoutExpired:
        logger.error("[update_grype_db] Timeout while updating Grype database")
        log_error('update_grype_db', 'Timeout after 300s')
        raise
    except FileNotFoundError:
        logger.error("[update_grype_db] Grype not found in PATH")
        log_error('update_grype_db', 'Grype not found in PATH')
        raise
    except Exception as e:
        logger.error(f"[update_grype_db] Unexpected error: {e}")
        log_error('update_grype_db', str(e))
        raise


@shared_task(name="tasks.scheduled_tasks.daily_rescan_all")
def daily_rescan_all():
    """
    Re-scans all active product SBOMs in batches of 8
    to avoid overloading CPU/RAM with too many concurrent Grype processes.
    """
    from tasks.scan_tasks import run_grype_scan

    uploads = list(SbomUpload.objects.filter(
        status='COMPLETED',
        product__active=True,
    ).select_related('product').order_by('uploaded_at'))

    if not uploads:
        logger.info("[daily_rescan_all] No active SBOMs found for re-scan.")
        log_task('daily_rescan_all', 'SUCCESS', sboms_found=0)
        return

    count = len(uploads)
    logger.info(f"[daily_rescan_all] Iniciando re-scan de {count} SBOMs em lotes de 8...")
    log_task('daily_rescan_all', 'STARTED', sboms_found=count)

    BATCH_SIZE = 8
    BATCH_DELAY = 30  # seconds between batches

    scheduled = 0
    errors = 0
    for i in range(0, count, BATCH_SIZE):
        batch = uploads[i:i + BATCH_SIZE]
        for upload in batch:
            try:
                chain(
                    run_grype_scan.si(str(upload.id)),
                    run_ingestion_update.si(str(upload.id)),
                ).apply_async(countdown=i // BATCH_SIZE * BATCH_DELAY)
                scheduled += 1
                logger.info(f"[daily_rescan_all] Re-scan scheduled: {upload.product.name} ({upload.id})")
            except Exception as e:
                errors += 1
                logger.error(f"[daily_rescan_all] Erro ao agendar {upload.id}: {e}")
                log_error('daily_rescan_all', str(e), upload_id=str(upload.id))

        logger.info(f"[daily_rescan_all] Batch {i // BATCH_SIZE + 1} scheduled — {len(batch)} SBOMs")

    log_task('daily_rescan_all', 'SUCCESS',
             sboms_found=count,
             sboms_scheduled=scheduled,
             errors=errors,
             batches=count // BATCH_SIZE + 1)
    logger.info(f"[daily_rescan_all] Done: {scheduled} scheduled, {errors} errors.")


@shared_task(name="tasks.scheduled_tasks.daily_integrity_check")
def daily_integrity_check():
    """
    Checks data integrity between PostgreSQL and Neo4j daily.
    Logs results to MongoDB — WARNING if inconsistencies are found.
    """
    import os
    import time
    from neo4j import GraphDatabase
    from apps.organizations.models import Product
    from apps.sbom.models import Component, Vulnerability

    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://matrix-graph:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "outra_senha_forte_aqui")

    start = time.time()
    issues = []
    log_task('daily_integrity_check', 'STARTED')

    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:

            # ── 1. Products PG → Neo4j ───────────────────────────────────
            pg_products = {
                p.id: p.name
                for p in Product.objects.filter(active=True)
            }
            neo4j_products = {
                r['db_id']: r['name']
                for r in session.run(
                    "MATCH (p:Product) WHERE p.db_id IS NOT NULL RETURN p.db_id AS db_id, p.name AS name"
                )
            }

            for pid, pname in pg_products.items():
                if pid not in neo4j_products:
                    issues.append(f"PRODUCT MISSING IN NEO4J: ID={pid} ({pname})")
                    logger.warning(f"[integrity] Product ID {pid} ({pname}) not found in Neo4j")

            # ── 2. Components PG → Neo4j ──────────────────────────────────
            pg_comps = set(
                Component.objects.filter(product__active=True)
                .values_list('name', 'version')
            )
            neo4j_comps = set(
                (r['name'], r['version'])
                for r in session.run(
                    "MATCH (c:Component) RETURN c.name AS name, c.version AS version"
                )
            )
            missing_comps = pg_comps - neo4j_comps
            if missing_comps:
                issues.append(f"{len(missing_comps)} components missing in Neo4j")
                for name, version in list(missing_comps)[:5]:
                    logger.warning(f"[integrity] Component missing in Neo4j: {name}@{version}")

            # ── 3. CVEs PG → Neo4j ──────────────────────────────────────
            pg_cve_count = Vulnerability.objects.filter(
                component__product__active=True
            ).count()
            neo4j_cve_count = session.run(
                "MATCH (c:Component)-[:HAS_VULNERABILITY]->(v:CVE) RETURN count(*) AS total"
            ).single()['total']

            if pg_cve_count != neo4j_cve_count:
                issues.append(f"CVEs: PG={pg_cve_count} vs Neo4j={neo4j_cve_count} (diff={abs(pg_cve_count - neo4j_cve_count)})")

        driver.close()

        duration = round(time.time() - start, 2)

        if issues:
            logger.warning(f"[integrity] {len(issues)} inconsistencies found")
            log_task('daily_integrity_check', 'WARNING',
                     duration_seconds=duration,
                     issues_count=len(issues),
                     issues=issues)
        else:
            logger.info("[integrity] PG and Neo4j are fully consistent")
            log_task('daily_integrity_check', 'SUCCESS',
                     duration_seconds=duration,
                     issues_count=0)

    except Exception as e:
        logger.error(f"[integrity] Erro: {e}")
        log_error('daily_integrity_check', str(e))
        raise
def run_ingestion_update(upload_id):
    """
    Variant of run_ingestion used for the daily re-scan.
    Updates existing CVEs in addition to creating new ones.
    """
    import os
    import json
    import time
    from django.conf import settings
    from apps.sbom.models import Component, Vulnerability
    from neo4j import GraphDatabase

    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://matrix-graph:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "outra_senha_forte_aqui")

    VULNS_DIR = os.path.join(settings.MEDIA_ROOT, "vulns")
    vuln_path = os.path.join(VULNS_DIR, f"{upload_id}.vulns.json")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    start = time.time()
    log_task('run_ingestion_update', 'STARTED', upload_id=upload_id)

    try:
        upload = SbomUpload.objects.get(id=upload_id)
        # Skip if the product is no longer active
        if not upload.product or not upload.product.active:
            logger.info(f"[run_ingestion_update] Produto inativo, pulando: {upload_id}")
            log_task('run_ingestion_update', 'SKIPPED',
                    upload_id=upload_id,
                    reason='product_inactive')
            return

        # Mark as re-scanning so the dashboard polling can detect it
        upload.status = 'PROCESSING'
        upload.save(update_fields=['status'])

        if not os.path.exists(vuln_path):
            logger.error(f"[run_ingestion_update] Arquivo não encontrado: {vuln_path}")
            return

        with open(vuln_path, 'r') as f:
            data = json.load(f)

        new_vulns = 0
        updated_vulns = 0

        with driver.session() as session:
            for match in data.get('matches', []):
                vuln_data = match.get('vulnerability', {})
                artifact = match.get('artifact', {})

                comp = Component.objects.filter(
                    product=upload.product,
                    name=artifact.get('name'),
                    version=artifact.get('version'),
                ).first()

                if not comp:
                    continue

                # Extract scores
                cvss_list = vuln_data.get('cvss', [])
                cvss_score = cvss_list[0].get('metrics', {}).get('baseScore') if cvss_list else None

                epss_list = vuln_data.get('epss', [])
                epss_score = epss_list[0].get('epss') if epss_list else None

                known_exploited_list = vuln_data.get('knownExploited', [])
                known_exploited = len(known_exploited_list) > 0
                known_ransomware = any(
                    k.get('knownRansomwareCampaignUse') == 'known'
                    for k in known_exploited_list
                )

                cve_id = vuln_data.get('id')
                severity = vuln_data.get('severity', 'UNKNOWN').upper()

                # Create or UPDATE the vulnerability record
                vuln, created = Vulnerability.objects.get_or_create(
                    component=comp,
                    cve_id=cve_id,
                    defaults={
                        'severity': severity,
                        'description': vuln_data.get('description', 'Sem descrição'),
                        'cvss_score': cvss_score,
                        'epss_score': epss_score,
                        'known_exploited': known_exploited,
                        'known_ransomware': known_ransomware,
                        'status': 'OPEN',
                    }
                )

                if created:
                    new_vulns += 1
                    logger.info(
                        f"[run_ingestion_update] NOVA CVE: {cve_id} | "
                        f"{comp.name}@{comp.version} | "
                        f"Severity={severity} CVSS={cvss_score} EPSS={epss_score} "
                        f"KEV={known_exploited} RAN={known_ransomware}"
                    )
                else:
                    # Detect and log each individual change
                    changes = []

                    if vuln.epss_score != epss_score:
                        changes.append(f"EPSS {vuln.epss_score}→{epss_score}")
                        vuln.epss_score = epss_score

                    if vuln.cvss_score != cvss_score:
                        changes.append(f"CVSS {vuln.cvss_score}→{cvss_score}")
                        vuln.cvss_score = cvss_score

                    if vuln.known_exploited != known_exploited:
                        changes.append(f"KEV {vuln.known_exploited}→{known_exploited}")
                        vuln.known_exploited = known_exploited

                    if vuln.known_ransomware != known_ransomware:
                        changes.append(f"RAN {vuln.known_ransomware}→{known_ransomware}")
                        vuln.known_ransomware = known_ransomware

                    if vuln.severity != severity:
                        changes.append(f"Severity {vuln.severity}→{severity}")
                        vuln.severity = severity

                    if changes:
                        vuln.save()
                        updated_vulns += 1
                        logger.info(
                            f"[run_ingestion_update] ATUALIZADO: {cve_id} | "
                            f"{comp.name}@{comp.version} | "
                            f"{' | '.join(changes)}"
                        )

                # Update Neo4j
                session.run("""
                    MATCH (c:Component {name: $pkg_name, version: $pkg_version})
                    MERGE (v:CVE {cveId: $cve_id})
                    SET v.severity = $severity,
                        v.epss = $epss,
                        v.knownExploited = $known_exploited,
                        v.knownRansomware = $known_ransomware
                    MERGE (c)-[:HAS_VULNERABILITY]->(v)
                """, {
                    "pkg_name": artifact.get('name'),
                    "pkg_version": artifact.get('version'),
                    "cve_id": cve_id,
                    "severity": severity,
                    "epss": epss_score or 0.0,
                    "known_exploited": known_exploited,
                    "known_ransomware": known_ransomware,
                })

        logger.info(
            f"[run_ingestion_update] {upload.product.name}: "
            f"{new_vulns} CVEs novas, {updated_vulns} atualizadas."
        )

        # Restore COMPLETED status after re-scan
        upload.status = 'COMPLETED'
        upload.save(update_fields=['status'])

        log_task('run_ingestion_update', 'SUCCESS',
                 upload_id=upload_id,
                 product=upload.product.name,
                 duration_seconds=round(time.time() - start, 2),
                 new_vulns=new_vulns,
                 updated_vulns=updated_vulns)

    except Exception as e:
        logger.error(f"[run_ingestion_update] Erro: {e}")
        log_error('run_ingestion_update', str(e), upload_id=upload_id)
        # Restore COMPLETED even on error — never leave stuck in PROCESSING
        try:
            SbomUpload.objects.filter(id=upload_id).update(status='COMPLETED')
        except Exception:
            pass
        raise
    finally:
        driver.close()