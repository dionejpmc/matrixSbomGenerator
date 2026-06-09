import subprocess
import os
import json
import logging
import time
from celery import shared_task, chain
from django.conf import settings
from apps.sbom.models import SbomUpload, Component, Vulnerability
from neo4j import GraphDatabase
from core.mongo import log_task, log_error

logger = logging.getLogger(__name__)

# Neo4j connection settings
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://matrix-graph:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "outra_senha_forte_aqui")

# Output directory for Grype results inside the shared volume
VULNS_DIR = os.path.join(settings.MEDIA_ROOT, "vulns")


@shared_task(name="run_full_scan")
def run_full_scan(upload_id):
    chain(
        run_grype_scan.si(upload_id),
        run_ingestion.si(upload_id),
    ).delay()


@shared_task(
    name="run_vulnerability_scan",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    time_limit=600,       # 10 min hard limit
    soft_time_limit=540,  # 9 min soft limit — permite cleanup
)
def run_grype_scan(self, upload_id):
    from celery.exceptions import SoftTimeLimitExceeded
    upload = SbomUpload.objects.get(id=upload_id)

    # Only mark as PROCESSING if it was already COMPLETED (re-scan case)
    # Initial uploads arrive as PROCESSING from sbom_tasks
    if upload.status == 'COMPLETED':
        SbomUpload.objects.filter(id=upload_id).update(status='PROCESSING')

    sbom_path = os.path.join(settings.MEDIA_ROOT, upload.sbom_file.name)
    os.makedirs(VULNS_DIR, exist_ok=True)
    output_path = os.path.join(VULNS_DIR, f"{upload_id}.vulns.json")
    start = time.time()
    log_task('run_grype_scan', 'STARTED',
             upload_id=upload_id,
             product=upload.product.name if upload.product else upload.product_name)
    try:
        command = ["grype", f"sbom:{sbom_path}", "-o", "json"]
        logger.info(f"[run_grype_scan] Iniciando scan: {sbom_path}")
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=540)

        with open(output_path, "w") as f:
            f.write(result.stdout)

        duration = round(time.time() - start, 2)
        logger.info(f"[run_grype_scan] Scan concluído para upload {upload_id}")
        log_task('run_grype_scan', 'SUCCESS',
                 upload_id=upload_id,
                 product=upload.product.name if upload.product else upload.product_name,
                 duration_seconds=duration)
    except SoftTimeLimitExceeded:
        logger.error(f"[run_grype_scan] Soft timeout para upload {upload_id}")
        log_error('run_grype_scan', 'Soft time limit excedido', upload_id=upload_id)
        SbomUpload.objects.filter(id=upload_id).update(status='COMPLETED')
        raise
    except subprocess.TimeoutExpired as e:
        logger.error(f"[run_grype_scan] Timeout no Grype: {upload_id}")
        log_error('run_grype_scan', 'Timeout no subprocess Grype', upload_id=upload_id)
        SbomUpload.objects.filter(id=upload_id).update(status='COMPLETED')
        raise self.retry(exc=e, countdown=60 * (self.request.retries + 1))
    except Exception as e:
        logger.error(f"[run_grype_scan] Erro no Grype: {str(e)}")
        log_error('run_grype_scan', str(e), upload_id=upload_id)
        SbomUpload.objects.filter(id=upload_id).update(status='COMPLETED')
        raise self.retry(exc=e, countdown=60 * (self.request.retries + 1))


@shared_task(name="run_ingestion")
def run_ingestion(upload_id):
    upload = SbomUpload.objects.get(id=upload_id)
    vuln_path = os.path.join(VULNS_DIR, f"{upload_id}.vulns.json")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    start = time.time()
    new_vulns = 0
    log_task('run_ingestion', 'STARTED',
             upload_id=upload_id,
             product=upload.product.name if upload.product else upload.product_name)

    try:
        if not os.path.exists(vuln_path):
            logger.error(f"[run_ingestion] Arquivo não encontrado: {vuln_path}")
            log_error('run_ingestion', 'Arquivo de vulnerabilidades não encontrado',
                      upload_id=upload_id, path=vuln_path)
            return

        with open(vuln_path, 'r') as f:
            data = json.load(f)

        with driver.session() as session:
            for match in data.get('matches', []):
                vuln_data = match.get('vulnerability', {})
                artifact = match.get('artifact', {})

                comp = Component.objects.filter(
                    product=upload.product,
                    name=artifact.get('name'),
                    version=artifact.get('version'),
                ).first()

                if comp:
                    cvss_list = vuln_data.get('cvss', [])
                    cvss_score = None
                    if cvss_list:
                        cvss_score = cvss_list[0].get('metrics', {}).get('baseScore')

                    epss_list = vuln_data.get('epss', [])
                    epss_score = epss_list[0].get('epss') if epss_list else None

                    known_exploited_list = vuln_data.get('knownExploited', [])
                    known_exploited = len(known_exploited_list) > 0
                    known_ransomware = any(
                        k.get('knownRansomwareCampaignUse') == 'known'
                        for k in known_exploited_list
                    )

                    _, created = Vulnerability.objects.get_or_create(
                        component=comp,
                        cve_id=vuln_data.get('id'),
                        defaults={
                            'severity': vuln_data.get('severity', 'UNKNOWN').upper(),
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
                        "cve_id": vuln_data.get('id'),
                        "severity": vuln_data.get('severity', 'UNKNOWN').upper(),
                        "epss": epss_score or 0.0,
                        "known_exploited": known_exploited,
                        "known_ransomware": known_ransomware,
                    })

        duration = round(time.time() - start, 2)
        logger.info(f"[run_ingestion] Ingestão concluída para upload {upload_id}")

        # Mark as COMPLETED after successful ingestion
        SbomUpload.objects.filter(id=upload_id).update(status='COMPLETED')

        log_task('run_ingestion', 'SUCCESS',
                 upload_id=upload_id,
                 product=upload.product.name if upload.product else upload.product_name,
                 duration_seconds=duration,
                 new_vulns=new_vulns)

    except Exception as e:
        logger.error(f"[run_ingestion] Erro: {str(e)}")
        log_error('run_ingestion', str(e), upload_id=upload_id)
        SbomUpload.objects.filter(id=upload_id).update(status='FAILED')
        raise e
    finally:
        driver.close()