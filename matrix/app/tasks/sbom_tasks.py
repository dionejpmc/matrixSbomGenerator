from celery import shared_task, chain
from django.db import transaction
from django.conf import settings
from apps.sbom.models import Component, SbomUpload, Vulnerability
from apps.organizations.models import Product
from neo4j import GraphDatabase
import json
import os
import logging
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Neo4j connection settings
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://matrix-graph:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "outra_senha_forte_aqui")


def _parse_purl(purl):
    """
    Extrai name e version de um PURL CycloneDX.
    Ex: pkg:deb/debian/adduser@3.118?arch=all → ('adduser', '3.118')
    """
    try:
        base = purl.split('?')[0]
        pkg = base.split('/')[-1]
        if '@' in pkg:
            name, version = pkg.split('@', 1)
            version = unquote(version)
            return name, version
        return pkg, None
    except Exception:
        return None, None


@shared_task(bind=True, name="tasks.sbom_tasks.process_sbom_task")
def process_sbom_task(self, upload_id):
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    upload = None
    try:
        upload = SbomUpload.objects.get(id=upload_id)

        # Skip duplicate check for CSV uploads
        if upload.source != 'csv':
            existing = SbomUpload.objects.filter(
                hashcode=upload.hashcode,
                status='COMPLETED',
                product__active=True
            ).exclude(id=upload.id).first()

            if existing:
                upload.status = 'FAILED'
                upload.error_message = f'SBOM duplicado — já existe um upload idêntico ativo: {existing.id}'
                upload.save()
                logger.warning(f'[process_sbom_task] SBOM duplicado detectado em produto ativo: {upload.id} = {existing.id}')
                return

        upload.status = 'PROCESSING'
        upload.save()

        # Use the product already linked by the view when available.
        # Otherwise (e.g. coming from the RAUC pipeline), find or create an active one.
        product = upload.product
        if not product:
            product, _ = Product.objects.get_or_create(
                name=upload.product_name,
                active=True,  # Busca/Cria um que esteja ativo com o nome limpo
                defaults={
                    'active': True
                }
            )
            upload.product = product
            upload.save()

        # 2. Resolve the absolute file path via MEDIA_ROOT
        sbom_path = os.path.join(settings.MEDIA_ROOT, upload.sbom_file.name)

        with open(sbom_path, 'r') as f:
            sbom_data = json.load(f)

        components_list = sbom_data.get('components') or sbom_data.get('artifacts') or []
        dependencies_list = sbom_data.get('dependencies', [])

        with driver.session() as session:

            # ── STEP 1: Save components to PostgreSQL and Neo4j ─────────────
            for item in components_list:
                name = item.get('name')
                version = item.get('version')
                if not name or not version:
                    continue

                purl = item.get('purl') or f"pkg:generic/{name}@{version}"
                comp_type = item.get('type', 'unknown')

                # SAVE TO POSTGRESQL
                with transaction.atomic():
                    Component.objects.get_or_create(
                        product=product,
                        name=name,
                        version=version,
                        defaults={"purl": purl, "type": comp_type}
                    )

                # SAVE TO NEO4J — uses db_id as the stable product key
                session.run("""
                    MERGE (p:Product {db_id: toInteger($prod_id)})
                    SET p.name = $prod_name,
                        p.active = true
                    MERGE (c:Component {name: $name, version: $version})
                    SET c.purl = $purl
                    MERGE (p)-[:HAS_COMPONENT]->(c)
                """, {
                    "prod_name": product.name,
                    "prod_id": product.id,
                    "purl": purl,
                    "name": name,
                    "version": version,
                })

            # ── STEP 2: Save dependencies to Neo4j (DEPENDS_ON) ─────────────
            dep_count = 0
            for dep_entry in dependencies_list:
                source_purl = dep_entry.get('ref')
                depends_on = dep_entry.get('dependsOn', [])

                if not source_purl or not depends_on:
                    continue

                src_name, src_version = _parse_purl(source_purl)
                if not src_name or not src_version:
                    continue

                for target_purl in depends_on:
                    tgt_name, tgt_version = _parse_purl(target_purl)
                    if not tgt_name or not tgt_version:
                        continue

                    # MERGE by name+version — same key used for components
                    session.run("""
                        MERGE (src:Component {name: $src_name, version: $src_version})
                        MERGE (tgt:Component {name: $tgt_name, version: $tgt_version})
                        MERGE (src)-[:DEPENDS_ON]->(tgt)
                    """, {
                        "src_name": src_name,
                        "src_version": src_version,
                        "tgt_name": tgt_name,
                        "tgt_version": tgt_version,
                    })
                    dep_count += 1

            logger.info(f"[process_sbom_task] {dep_count} relações DEPENDS_ON criadas no Neo4j")

        upload.status = 'COMPLETED'
        upload.save()

        # 3. Trigger the vulnerability scan pipeline in sequence
        from tasks.scan_tasks import run_grype_scan, run_ingestion
        chain(
            run_grype_scan.si(upload_id),
            run_ingestion.si(upload_id),
        ).delay()

    except Exception as e:
        logger.error(f"ERRO NA TASK: {str(e)}")
        if upload:
            upload.status = 'FAILED'
            upload.error_message = str(e)
            upload.save()
        raise e
    finally:
        driver.close()