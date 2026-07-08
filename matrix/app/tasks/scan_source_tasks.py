"""
scan_source_tasks.py — Processamento de SBOM originado do SCAN DE CÓDIGO-FONTE.

────────────────────────────────────────────────────────────────────────────
POR QUE ESTE ARQUIVO EXISTE (decisão de arquitetura — não reunir com sbom_tasks)
────────────────────────────────────────────────────────────────────────────
O Matrix processa SBOMs de duas origens conceitualmente distintas:

  1. SBOM .json / RAUC  →  tratado por tasks/sbom_tasks.py::process_sbom_task
     Vem de um arquivo CycloneDX real: componentes com purl/versão reais e uma
     seção `dependencies` nativa. As relações DEPENDS_ON saem dessa seção,
     cruzando purls (name@version).

  2. SBOM do scan de código-fonte (firmware bare-metal)  →  ESTE ARQUIVO
     Vem do scanner de pastas: componentes de PRIMEIRA PARTE (arquivos .c/.h do
     próprio firmware), em geral SEM versão real (version='unknown') e SEM purl.
     As dependências NÃO vêm de uma seção CycloneDX — vêm do campo
     Component.depends (os #include crus, ex.: "ADC.h, UserIO.h"), que são
     casados com componentes existentes pelo NOME DE ARQUIVO (com extensão:
     um include de UserIO.h aponta para o header UserIO.h, não para UserIO.c),
     já que não há purl/versão para casar.

Esses dois fluxos divergem exatamente na leitura de componentes e na montagem
do grafo de dependências. Forçá-los pelo mesmo código exigiria condicionais
frágeis ("se csv faz X, senão Y") no meio de process_sbom_task, e um ajuste no
fluxo novo poderia quebrar o fluxo .json (que já roda em produção).

DECISÃO: separar SOMENTE o que diverge (a montagem de componentes + DEPENDS_ON),
numa task própria — process_scan_source_task —, e REUTILIZAR a infraestrutura
comum de scan de vulnerabilidade (run_grype_scan e run_ingestion de
tasks/scan_tasks.py), que é idêntica para os dois fluxos. Assim:
  • o fluxo .json (process_sbom_task) fica INTOCADO — zero risco de regressão;
  • não duplicamos Grype/ingestão — um único lugar para manter essa lógica;
  • o fluxo do scan de pastas ganha resolução de dependências por nome, correta
    para componentes first-party sem versão.

NÃO reúna esta task com process_sbom_task "para simplificar": a separação é
intencional e protege o fluxo .json. Se a lógica de Grype/ingestão mudar,
mude em tasks/scan_tasks.py (compartilhado) — nunca duplique aqui.
────────────────────────────────────────────────────────────────────────────
"""

import os
import logging

from celery import shared_task, chain
from django.conf import settings

from apps.sbom.models import Component, SbomUpload
from apps.organizations.models import Product
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

# Neo4j connection settings (mesmas envs usadas por sbom_tasks/scan_tasks)
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://matrix-graph:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "outra_senha_forte_aqui")


def _include_basename(header: str) -> str:
    """'mbedtls/ssl.h' -> 'ssl.h' ; 'UserIO.h' -> 'UserIO.h'.
    Extrai só o nome do arquivo do include (com extensão), para casar com o
    componente de mesmo nome. NÃO remove a extensão: um include de 'UserIO.h'
    aponta para o header UserIO.h, não para UserIO.c — cada arquivo é um nó."""
    return header.replace("\\", "/").split("/")[-1].strip().lower()


@shared_task(bind=True, name="tasks.scan_source_tasks.process_scan_source_task")
def process_scan_source_task(self, upload_id):
    """
    Processa um SBOM originado do scan de código-fonte:
      • cria/atualiza os nós Component e a relação (Product)-[:HAS_COMPONENT]->(Component)
        no Neo4j, a partir dos Component já gravados no PostgreSQL;
      • cria (Component)-[:DEPENDS_ON]->(Component) resolvendo os #include crus
        do campo Component.depends para componentes existentes do MESMO produto,
        casando por NOME normalizado (sem extensão, case-insensitive);
      • ao final, dispara o pipeline comum de vulnerabilidade
        (run_grype_scan → run_ingestion), reutilizado de tasks/scan_tasks.py.

    Diferente de process_sbom_task, NÃO lê a seção `dependencies` de um
    CycloneDX: a fonte de verdade das dependências aqui é Component.depends.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    upload = None
    try:
        upload = SbomUpload.objects.get(id=upload_id)
        upload.status = 'PROCESSING'
        upload.save(update_fields=['status'])

        product = upload.product
        if not product:
            product, _ = Product.objects.get_or_create(
                name=upload.product_name, active=True, defaults={'active': True}
            )
            upload.product = product
            upload.save(update_fields=['product'])

        components = list(Component.objects.filter(product=product))

        # índice nome-de-arquivo -> componente, para resolver os includes.
        # A chave é o nome COM extensão (ADC.h, ADC.c distintos). Um include de
        # "UserIO.h" casa com o componente UserIO.h; o UserIO.c é um nó à parte
        # que ninguém inclui (em C inclui-se o header, não o .c).
        by_name = {}
        for c in components:
            key = _include_basename(c.name)
            by_name.setdefault(key, c)

        dep_count = 0
        with driver.session() as session:
            # ── STEP 1: nós Component + HAS_COMPONENT ──────────────────────
            for c in components:
                session.run(
                    """
                    MERGE (p:Product {db_id: toInteger($prod_id)})
                    SET p.name = $prod_name, p.active = true
                    MERGE (c:Component {name: $name, version: $version})
                    SET c.purl     = $purl,
                        c.type     = $type,
                        c.scope    = $scope,
                        c.supplier = $supplier,
                        c.license  = $license,
                        c.author   = $author,
                        c.depends  = $depends,
                        c.folder   = $folder
                    MERGE (p)-[:HAS_COMPONENT]->(c)
                    """,
                    {
                        "prod_id": product.id,
                        "prod_name": product.name,
                        "name": c.name,
                        "version": c.version or "unknown",
                        "purl": c.purl or "",
                        "type": c.type or "",
                        "scope": getattr(c, "scope", "") or "",
                        "supplier": c.supplier or "",
                        "license": c.license or "",
                        "author": c.author or "",
                        "depends": c.depends or "",
                        "folder": c.folder or "",
                    },
                )

            # ── STEP 2: DEPENDS_ON resolvendo includes -> componentes ──────
            for c in components:
                if not c.depends:
                    continue
                src_name_key = _include_basename(c.name)
                seen_targets = set()
                for raw_inc in c.depends.split(","):
                    inc = raw_inc.strip()
                    if not inc:
                        continue
                    tgt_key = _include_basename(inc)
                    # ignora auto-dependência (arquivo incluindo a si mesmo)
                    if tgt_key == src_name_key:
                        continue
                    target = by_name.get(tgt_key)
                    if not target:
                        continue  # include sem componente correspondente (ex.: string.h)
                    if target.id in seen_targets:
                        continue
                    seen_targets.add(target.id)
                    session.run(
                        """
                        MATCH (src:Component {name: $src_name, version: $src_version})
                        MATCH (tgt:Component {name: $tgt_name, version: $tgt_version})
                        MERGE (src)-[:DEPENDS_ON]->(tgt)
                        """,
                        {
                            "src_name": c.name,
                            "src_version": c.version or "unknown",
                            "tgt_name": target.name,
                            "tgt_version": target.version or "unknown",
                        },
                    )
                    dep_count += 1

        logger.info(f"[process_scan_source_task] {dep_count} relações DEPENDS_ON criadas no Neo4j")

        upload.status = 'COMPLETED'
        upload.save(update_fields=['status'])

        # ── Pipeline comum de vulnerabilidade (reutilizado, não duplicado) ──
        from tasks.scan_tasks import run_grype_scan, run_ingestion
        chain(
            run_grype_scan.si(upload_id),
            run_ingestion.si(upload_id),
        ).delay()

    except Exception as e:
        logger.error(f"[process_scan_source_task] ERRO: {e}")
        if upload:
            upload.status = 'FAILED'
            upload.error_message = str(e)
            upload.save(update_fields=['status', 'error_message'])
        raise e
    finally:
        driver.close()