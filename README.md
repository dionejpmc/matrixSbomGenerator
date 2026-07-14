# WISM – WEG Integrated SBOM Manager

O WISM é uma plataforma Django para gestão de segurança de produtos embarcados, com foco em ingestão e análise de SBOMs, rastreio de vulnerabilidades, declarações VEX, análise de firmware (RAUC/EXT4), inventário hardware (HBOM), modelagem EMB3D e workflows de aprovação e auditoria.

A versão atual do projeto já inclui um dashboard central, pipeline assíncrono com Celery, integração com Neo4j, PostgreSQL, Redis e MongoDB, autenticação local/OIDC, módulos de hunting, archive e feedback.

---

## Visão geral

O projeto é composto por uma aplicação web Django 5, serviços Docker para banco de dados e infraestrutura de processamento e workers Celery para executar análises de SBOM e firmware.

### Funcionalidades principais

- Upload e processamento de SBOMs em formatos CycloneDX e CSV manual
- Scan de vulnerabilidades com Grype e enriquecimento com CVSS/EPSS/KEV
- Declaração e exportação de VEX em formato compatível com CycloneDX 1.5
- Upload de firmware RAUC e imagens EXT4 com extração e geração de SBOM
- Inventário hardware (HBOM) com associação a ameaças EMB3D e mitigação
- Módulo de Hunting para buscas transversais por componente, CVE e PURL
- Workflow de aprovação de uploads manuais e arquivamento de produtos desativados
- Canal de feedback integrado ao dashboard
- Controle de acesso por grupos e Business Units

---

## Arquitetura atual

O ambiente é orquestrado com Docker Compose e inclui os seguintes serviços:

| Serviço | Função |
|---|---|
| matrix-app | Aplicação Django web |
| matrix-db | PostgreSQL |
| matrix-graph | Neo4j |
| matrix-mongo | MongoDB para logs e auditoria |
| matrix-redis | Redis como broker e backend do Celery |
| matrix-worker | Worker Celery para processamento padrão |
| matrix-worker-rauc | Worker Celery para pipeline RAUC/EXT4 |
| matrix-beat | Celery Beat para tarefas agendadas |

A aplicação roda em portas locais padrão:

- Aplicação web: http://localhost:8000
- Django Admin: http://localhost:8000/admin
- Neo4j Browser: http://localhost:7474

---

## Estrutura do projeto

```text
matrix/
├── app/
│   ├── apps/
│   │   ├── accounts/        # autenticação, OIDC, RBAC, gestão de usuários
│   │   ├── archive/         # produtos arquivados e exportação
│   │   ├── feedback/        # canal de feedback
│   │   ├── hbom/            # inventário hardware e EMB3D
│   │   ├── hunting/         # busca e análise de vulnerabilidades
│   │   ├── organizations/   # Business Units e relacionamento com produtos
│   │   ├── rootfs/          # upload e processamento de RAUC/EXT4
│   │   └── sbom/            # SBOM, VEX, aprovação e scan source
│   ├── config/             # settings, URLs e configuração Django
│   ├── core/               # Celery e utilidades centrais
│   ├── tasks/              # tarefas assíncronas e agendadas
│   ├── templates/          # templates do dashboard e módulos UI
│   └── locale/             # traduções pt-BR/en
├── docker/
│   └── app/Dockerfile
├── docker-compose.yml
└── uploads/                # arquivos carregados e artefatos temporários
```

---

## Fluxos suportados

### 1. SBOM

A aplicação aceita:

- SBOMs CycloneDX JSON via upload tradicional
- Upload manual via CSV para revisão administrativa
- Scan de código-fonte por endpoint dedicado para pré-preenchimento de componentes

O fluxo padrão segue:

1. Upload
2. Validação / aprovação, quando aplicável
3. Processamento assíncrono
4. Armazenamento em PostgreSQL + Neo4j
5. Geração de dados para dashboard, VEX e hunting

### 2. Firmware e imagens

Os workers RAUC/EXT4 suportam:

- upload de arquivos .raucb
- upload de imagens .ext4
- montagem temporária e geração de SBOM via Syft
- disparo do pipeline de análise e ingestão

### 3. VEX e vulnerabilidades

A aplicação cria registros de vulnerabilidade por componente e permite:

- consultar detalhes de CVE
- declarar VEX por vulnerabilidade
- exportar VEX/CycloneDX para conformidade

### 4. Dashboard e gestão

O dashboard central concentra:

- estatísticas de SBOMs e vulnerabilidades
- upload de novos artefatos
- navegação para aprovação, hunting, archive e gestão de usuários
- feedback do usuário para melhorias e problemas

---

## Autenticação e permissões

O projeto suporta dois caminhos de autenticação:

- OIDC com Keycloak via mozilla-django-oidc
- autenticação local Django como fallback

Os acessos são controlados por grupos:

- Administrador: acesso completo
- Operador: leitura/escrita em uploads e workflows operacionais
- Viewer: leitura e consulta de dados

A aplicação também faz isolamento por Business Unit, filtrando consultas conforme o contexto do usuário.

---

## Execução rápida

### Requisitos

- Docker 24+
- Docker Compose 2.20+
- 4 GB RAM
- 20 GB de espaço em disco

### 1. Clone e prepare o ambiente

```bash
git clone <repo-url>
cd matrix
```

Crie um arquivo `.env` na raiz do projeto com as variáveis mínimas abaixo:

```env
SECRET_KEY=troque-por-uma-chave-segura
DEBUG=False

POSTGRES_DB=matrix
POSTGRES_USER=matrix
POSTGRES_PASSWORD=matrix-password

NEO4J_USER=neo4j
NEO4J_PASSWORD=neo4j-password

REDIS_PASSWORD=redis-password
CELERY_BROKER_URL=redis://:redis-password@redis:6379/0

MONGO_USER=matrix_mongo
MONGO_PASSWORD=mongo-password

OIDC_RP_CLIENT_ID=matrix-sbom
OIDC_RP_CLIENT_SECRET=changeme
OIDC_OP_BASE_URL=https://seu-keycloak/realms/seu-realm
```

### 2. Suba os containers

```bash
docker compose up -d
```

### 3. Aplique as migrações

```bash
docker compose exec app python manage.py migrate
```

### 4. Crie os grupos de RBAC

```bash
docker compose exec app python manage.py setup_groups
```

### 5. Crie um superusuário

```bash
docker compose exec app python manage.py createsuperuser
```

---

## Observações importantes

### Loop devices para RAUC/EXT4

Os fluxos de firmware montam imagens usando loop devices. Em hosts Linux, pode ser necessário ajustar o limite do kernel antes de iniciar o stack:

```bash
sudo modprobe loop max_loop=64
```

Para deixar permanente:

```bash
echo "options loop max_loop=64" | sudo tee /etc/modprobe.d/loop.conf
sudo update-initramfs -u
```

### Traduções

A interface suporta português e inglês. Para recompilar as traduções após editar os arquivos `.po`:

```bash
cd matrix/app
msgfmt locale/en/LC_MESSAGES/django.po -o locale/en/LC_MESSAGES/django.mo
msgfmt locale/pt_BR/LC_MESSAGES/django.po -o locale/pt_BR/LC_MESSAGES/django.mo
```

---

## Tarefas Celery

As tarefas assíncronas são executadas por Celery e incluem:

- atualização do banco de vulnerabilidades Grype
- revarredura diária de SBOMs
- verificação de integridade entre PostgreSQL e Neo4j
- processamento de SBOM, RAUC e EXT4

---

## Desenvolvimento

Comandos úteis durante o desenvolvimento:

```bash
# ver logs da aplicação
 docker compose logs -f app

# reiniciar a aplicação
 docker compose restart app

# entrar no container da aplicação
 docker compose exec app bash
```

---

## Status atual

Este README foi atualizado para refletir a estrutura e os fluxos atualmente implementados no repositório, incluindo os módulos de dashboard, SBOM, RAUC/EXT4, HBOM/EMB3D, hunting, archive, feedback e gestão de usuários.
