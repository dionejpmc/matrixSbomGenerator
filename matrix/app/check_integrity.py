#!/usr/bin/env python3
"""
check_integrity.py

Script standalone para verificar integridade entre PostgreSQL e Neo4j.
Roda FORA da aplicação Django — não precisa do ambiente configurado.

Uso:
    python check_integrity.py
    python check_integrity.py --verbose
    python check_integrity.py --fix        # tenta corrigir divergências simples

Dependências:
    pip install psycopg2-binary neo4j python-dotenv

Variáveis de ambiente (ou edite direto abaixo):
    POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
"""

import os
import sys
import argparse
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Tenta carregar .env se existir
# ─────────────────────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv opcional

# ─────────────────────────────────────────────────────────────
# CONFIGURAÇÃO — edite aqui se não usar variáveis de ambiente
# ─────────────────────────────────────────────────────────────
PG_CONFIG = {
    'host':     os.getenv('POSTGRES_HOST', 'localhost'),
    'port':     os.getenv('POSTGRES_PORT', '5432'),
    'dbname':   os.getenv('POSTGRES_DB', 'matrix'),
    'user':     os.getenv('POSTGRES_USER', 'matrix_user'),
    'password': os.getenv('POSTGRES_PASSWORD', ''),
}

NEO4J_URI      = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER     = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', '')

# ─────────────────────────────────────────────────────────────
# CORES para output
# ─────────────────────────────────────────────────────────────
GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

def ok(msg):      print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg):    print(f"  {RED}✗{RESET} {msg}")
def warn(msg):    print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg):    print(f"  {CYAN}→{RESET} {msg}")
def header(msg):  print(f"\n{BOLD}{msg}{RESET}\n" + "─" * 60)
def pg2neo(msg):  print(f"  {RED}✗ [PG→NEO4J]{RESET} {msg}")
def neo2pg(msg):  print(f"  {YELLOW}⚠ [NEO4J→PG]{RESET} {msg}")


# ─────────────────────────────────────────────────────────────
# CONEXÕES
# ─────────────────────────────────────────────────────────────

def connect_postgres():
    try:
        import psycopg2
        conn = psycopg2.connect(**PG_CONFIG)
        return conn
    except Exception as e:
        print(f"{RED}[ERRO] PostgreSQL: {e}{RESET}")
        sys.exit(1)


def connect_neo4j():
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
        return driver
    except Exception as e:
        print(f"{RED}[ERRO] Neo4j: {e}{RESET}")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────
# CHECKS
# ─────────────────────────────────────────────────────────────

def check_connections(pg_conn, neo4j_driver):
    header("1. Conectividade")

    # PostgreSQL
    try:
        cur = pg_conn.cursor()
        cur.execute("SELECT version()")
        version = cur.fetchone()[0].split(',')[0]
        ok(f"PostgreSQL conectado — {version}")
    except Exception as e:
        fail(f"PostgreSQL: {e}")

    # Neo4j
    try:
        with neo4j_driver.session() as session:
            result = session.run("RETURN 1 AS n")
            result.single()
            ok(f"Neo4j conectado — {NEO4J_URI}")
    except Exception as e:
        fail(f"Neo4j: {e}")


def check_product_sync(pg_conn, neo4j_driver, verbose=False):
    header("2. Sincronização de Produtos")

    cur = pg_conn.cursor()
    cur.execute("""
        SELECT id, name FROM organizations_product
        WHERE active = true
        ORDER BY name
    """)
    pg_products = {row[0]: row[1] for row in cur.fetchall()}
    info(f"PostgreSQL: {len(pg_products)} produtos ativos")

    with neo4j_driver.session() as session:
        result = session.run("MATCH (p:Product) RETURN p.db_id as id, p.name as name")
        neo4j_products = {int(r['id']): r['name'] for r in result if r['id'] is not None}
    info(f"Neo4j: {len(neo4j_products)} produtos")

    # Produtos no PG mas não no Neo4j
    missing_in_neo4j = set(pg_products.keys()) - set(neo4j_products.keys())
    if missing_in_neo4j:
        for pid in missing_in_neo4j:
            pg2neo(f"Produto ID {pid} ({pg_products[pid]}) — existe no PG mas NÃO no Neo4j")
    else:
        ok("[PG→NEO4J] Todos os produtos ativos do PG existem no Neo4j")

    # Produtos no Neo4j mas não no PG (órfãos)
    orphans = set(neo4j_products.keys()) - set(pg_products.keys())
    if orphans:
        for pid in orphans:
            neo2pg(f"Produto ID {pid} ({neo4j_products[pid]}) — existe no Neo4j mas NÃO no PG ativo")
    else:
        ok("[NEO4J→PG] Nenhum produto órfão no Neo4j")

    return missing_in_neo4j, orphans


def check_component_sync(pg_conn, neo4j_driver, verbose=False):
    header("3. Sincronização de Componentes")

    cur = pg_conn.cursor()
    cur.execute("""
        SELECT c.name, c.version
        FROM sbom_component c
        JOIN organizations_product p ON c.product_id = p.id
        WHERE p.active = true
        GROUP BY c.name, c.version
    """)
    pg_components = set(cur.fetchall())
    info(f"PostgreSQL: {len(pg_components)} componentes únicos (produtos ativos)")

    with neo4j_driver.session() as session:
        result = session.run("MATCH (c:Component) RETURN c.name as name, c.version as version")
        neo4j_components = set((r['name'], r['version']) for r in result)
    info(f"Neo4j: {len(neo4j_components)} componentes")

    missing = pg_components - neo4j_components
    if missing:
        pg2neo(f"{len(missing)} componentes existem no PG mas NÃO no Neo4j")
        if verbose:
            for name, version in list(missing)[:20]:
                info(f"  Faltando: {name}@{version}")
            if len(missing) > 20:
                info(f"  ... e mais {len(missing)-20}")
    else:
        ok("[PG→NEO4J] Todos os componentes do PG existem no Neo4j")

    orphans = neo4j_components - pg_components
    if orphans:
        neo2pg(f"{len(orphans)} componentes existem no Neo4j mas NÃO no PG ativo")
        if verbose:
            for name, version in list(orphans)[:10]:
                info(f"  Órfão: {name}@{version}")
    else:
        ok("[NEO4J→PG] Nenhum componente órfão no Neo4j")

    return missing, orphans


def check_vulnerability_sync(pg_conn, neo4j_driver, verbose=False):
    header("4. Sincronização de Vulnerabilidades (CVEs)")

    cur = pg_conn.cursor()
    cur.execute("""
        SELECT v.cve_id, c.name, c.version
        FROM sbom_vulnerability v
        JOIN sbom_component c ON v.component_id = c.id
        JOIN organizations_product p ON c.product_id = p.id
        WHERE p.active = true
        ORDER BY v.cve_id
    """)
    pg_vulns = set(cur.fetchall())
    info(f"PostgreSQL: {len(pg_vulns)} vínculos CVE→Componente (produtos ativos)")

    with neo4j_driver.session() as session:
        result = session.run("""
            MATCH (c:Component)-[:HAS_VULNERABILITY]->(v:CVE)
            RETURN v.cveId as cve_id, c.name as comp_name, c.version as comp_version
        """)
        neo4j_vulns = set((r['cve_id'], r['comp_name'], r['comp_version']) for r in result)
    info(f"Neo4j: {len(neo4j_vulns)} vínculos CVE→Componente")

    missing = pg_vulns - neo4j_vulns
    if missing:
        pg2neo(f"{len(missing)} vínculos existem no PG mas NÃO no Neo4j")
        if verbose:
            for cve, comp, ver in list(missing)[:20]:
                info(f"  Faltando: {cve} → {comp}@{ver}")
            if len(missing) > 20:
                info(f"  ... e mais {len(missing)-20}")
    else:
        ok("[PG→NEO4J] Todos os vínculos CVE→Componente do PG existem no Neo4j")

    orphans = neo4j_vulns - pg_vulns
    if orphans:
        neo2pg(f"{len(orphans)} vínculos existem no Neo4j mas NÃO no PG ativo")
        if verbose:
            for cve, comp, ver in list(orphans)[:10]:
                info(f"  Órfão: {cve} → {comp}@{ver}")
    else:
        ok("[NEO4J→PG] Nenhum vínculo CVE órfão no Neo4j")

    return missing, orphans


def check_kev_consistency(pg_conn, neo4j_driver):
    header("5. Consistência KEV e Ransomware")

    cur = pg_conn.cursor()
    cur.execute("""
        SELECT v.cve_id, v.known_exploited, v.known_ransomware,
               v.epss_score, v.severity
        FROM sbom_vulnerability v
        JOIN sbom_component c ON v.component_id = c.id
        JOIN organizations_product p ON c.product_id = p.id
        WHERE p.active = true
          AND (v.known_exploited = true OR v.known_ransomware = true)
    """)
    pg_kev = {row[0]: {'kev': row[1], 'ran': row[2], 'epss': row[3], 'sev': row[4]}
              for row in cur.fetchall()}
    info(f"PostgreSQL: {len(pg_kev)} CVEs com KEV ou Ransomware")

    with neo4j_driver.session() as session:
        result = session.run("""
            MATCH (v:CVE)
            WHERE v.knownExploited = true OR v.knownRansomware = true
            RETURN v.cveId as cve_id,
                   v.knownExploited as kev,
                   v.knownRansomware as ran,
                   v.severity as sev
        """)
        neo4j_kev = {r['cve_id']: {'kev': r['kev'], 'ran': r['ran'], 'sev': r['sev']}
                     for r in result}
    info(f"Neo4j: {len(neo4j_kev)} CVEs com KEV ou Ransomware")

    divergencias = []
    for cve_id, pg_data in pg_kev.items():
        neo_data = neo4j_kev.get(cve_id)
        if not neo_data:
            divergencias.append(f"[PG→NEO4J] {cve_id}: marcado como KEV/RAN no PG mas não no Neo4j")
        elif neo_data['kev'] != pg_data['kev'] or neo_data['ran'] != pg_data['ran']:
            divergencias.append(
                f"[DIVERGÊNCIA] {cve_id}: "
                f"KEV PG={pg_data['kev']} Neo4j={neo_data['kev']} | "
                f"RAN PG={pg_data['ran']} Neo4j={neo_data['ran']}"
            )

    # Verifica também sentido inverso — KEV no Neo4j mas não no PG
    for cve_id, neo_data in neo4j_kev.items():
        if cve_id not in pg_kev:
            divergencias.append(f"[NEO4J→PG] {cve_id}: marcado como KEV/RAN no Neo4j mas não no PG ativo")

    if divergencias:
        fail(f"{len(divergencias)} divergências KEV/RAN entre PG e Neo4j:")
        for d in divergencias[:10]:
            info(f"  {d}")
    else:
        ok("[PG↔NEO4J] KEV e Ransomware consistentes nas duas direções")


def check_counts_summary(pg_conn, neo4j_driver):
    header("6. Resumo de Contagens")

    cur = pg_conn.cursor()

    cur.execute("SELECT COUNT(*) FROM organizations_product WHERE active = true")
    pg_products = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(DISTINCT (c.name, c.version))
        FROM sbom_component c
        JOIN organizations_product p ON c.product_id = p.id
        WHERE p.active = true
    """)
    pg_components = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM sbom_vulnerability v
        JOIN sbom_component c ON v.component_id = c.id
        JOIN organizations_product p ON c.product_id = p.id
        WHERE p.active = true
    """)
    pg_vulns = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM sbom_vulnerability v
        JOIN sbom_component c ON v.component_id = c.id
        JOIN organizations_product p ON c.product_id = p.id
        WHERE p.active = true AND v.known_exploited = true
    """)
    pg_kev = cur.fetchone()[0]

    with neo4j_driver.session() as session:
        neo4j_products   = session.run("MATCH (p:Product) RETURN count(p) as n").single()['n']
        neo4j_components = session.run("MATCH (c:Component) RETURN count(c) as n").single()['n']
        neo4j_vulns      = session.run("MATCH ()-[:HAS_VULNERABILITY]->() RETURN count(*) as n").single()['n']
        neo4j_kev        = session.run("MATCH (v:CVE) WHERE v.knownExploited=true RETURN count(v) as n").single()['n']

    print(f"\n  {'Métrica':<30} {'PostgreSQL':>12} {'Neo4j':>12} {'Status':>10}")
    print("  " + "─" * 68)

    def row(label, pg, neo):
        status = f"{GREEN}OK{RESET}" if pg == neo else f"{YELLOW}DIFF{RESET}"
        print(f"  {label:<30} {pg:>12} {neo:>12}   {status}")

    row("Produtos ativos", pg_products, neo4j_products)
    row("Componentes únicos", pg_components, neo4j_components)
    row("Vínculos CVE→Componente", pg_vulns, neo4j_vulns)
    row("CVEs KEV", pg_kev, neo4j_kev)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Verifica integridade PostgreSQL ↔ Neo4j')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mostra detalhes das divergências')
    parser.add_argument('--only', choices=['conn', 'products', 'components', 'vulns', 'kev', 'summary'],
                        help='Roda apenas um check específico')
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}")
    print(f"  Matrix — Integrity Check")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}{RESET}")
    print(f"\n  PostgreSQL: {PG_CONFIG['host']}:{PG_CONFIG['port']}/{PG_CONFIG['dbname']}")
    print(f"  Neo4j:      {NEO4J_URI}")

    pg_conn      = connect_postgres()
    neo4j_driver = connect_neo4j()

    try:
        if not args.only or args.only == 'conn':
            check_connections(pg_conn, neo4j_driver)

        if not args.only or args.only == 'products':
            check_product_sync(pg_conn, neo4j_driver, args.verbose)

        if not args.only or args.only == 'components':
            check_component_sync(pg_conn, neo4j_driver, args.verbose)

        if not args.only or args.only == 'vulns':
            check_vulnerability_sync(pg_conn, neo4j_driver, args.verbose)

        if not args.only or args.only == 'kev':
            check_kev_consistency(pg_conn, neo4j_driver)

        if not args.only or args.only == 'summary':
            check_counts_summary(pg_conn, neo4j_driver)

    finally:
        pg_conn.close()
        neo4j_driver.close()

    print(f"\n{BOLD}{'='*60}{RESET}\n")


if __name__ == '__main__':
    main()
