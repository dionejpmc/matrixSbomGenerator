# Matrix SBOM Monitor

Web platform for embedded product security management: SBOM ingestion, vulnerability scanning, VEX statements, hardware inventory (HBOM) with EMB3D threat modeling, firmware analysis (RAUC/EXT4), and a navigable dependency graph.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          matrix_net (Docker bridge)                 │
│                                                                     │
│  Browser ──HTTP──► matrix-app (Django :8000)                        │
│                         │                                           │
│              ┌──────────┼──────────────┬──────────────┐             │
│              ▼          ▼              ▼              ▼             │
│         matrix-db   matrix-graph   matrix-mongo   matrix-redis      │
│        (Postgres)    (Neo4j)       (MongoDB)       (Redis)          │
│                                                    ▲    ▲           │
│                                                    │    │           │
│                              matrix-worker ────────┘    │           │
│                         (Celery + Grype scanner)        │           │
│                              matrix-worker-rauc ────────┘           │
│                         (Celery + Syft + mount)                     │
│                              matrix-beat                            │
│                         (Celery cron scheduler)                     │
└─────────────────────────────────────────────────────────────────────┘
```

| Container | Image | Role |
|-----------|-------|------|
| `matrix-app` | Python / Django 5 | Web application |
| `matrix-db` | PostgreSQL 15 | Relational data |
| `matrix-graph` | Neo4j 5 Community | Dependency graph |
| `matrix-mongo` | MongoDB 7 | Audit logs and task logs |
| `matrix-redis` | Redis 7 | Celery broker / session cache |
| `matrix-worker` | Python / Celery | Async tasks + Grype scanner |
| `matrix-worker-rauc` | Python / Celery | RAUC/EXT4 pipeline (Syft + mount) |
| `matrix-beat` | Python / Celery Beat | Scheduled jobs |

**Data flow:**

```
SBOM upload (CycloneDX JSON)  ─┐
Manual CSV input               ├──► Celery: parse → Grype scan → ingest results
RAUC bundle (.raucb)          ─┤         │              │
EXT4 image (.ext4)            ─┘         ▼              ▼
                                    PostgreSQL        Neo4j
                              (components, CVEs,  (Product→Component
                               VEX statements)     →CVE graph)
                                         │
                                    MongoDB (audit_logs, task_logs, error_logs)
```

---

## Features

| Module | Capability |
|--------|-----------|
| **SBOM** | Chunked upload, SHA-256 deduplication, CycloneDX JSON parsing |
| **Vulnerability scanning** | Grype integration: CVSS, EPSS and CISA KEV data |
| **VEX** | Statements per CISA spec (4 statuses × 5 justifications); automatic versioning |
| **CRA export** | CycloneDX 1.5 aligned with EU Cyber Resilience Act 2024/2847 |
| **HBOM** | Hardware component inventory with type and interface classification |
| **EMB3D** | MITRE EMB3D threat mapping from STIX 2.1 dataset; per-analyst mitigation tracking |
| **RAUC pipeline** | unsquashfs → mount ext4 → SBOM via Syft → Grype scan → Neo4j |
| **EXT4 pipeline** | Mount via loop device → read `/etc/os-release` → SBOM via Syft → Grype scan |
| **Dependency graph** | Neo4j: transitive DEPENDS_ON traversal; visualized via Cytoscape.js |
| **Vulnerability hunting** | Search by component, CVE and PURL across all BU products |
| **Approval workflow** | SBOM review and approve/reject before consolidation |
| **Historical archive** | Deactivated products accessible for audit and export |
| **Audit trail** | MongoDB: every action (VEX, upload, deactivation, download) recorded with user and IP |
| **Scheduled jobs** | Celery Beat: Grype DB update (02:00), SBOM rescan (03:00), PG↔Neo4j integrity (05:00) |
| **i18n** | Full interface in Portuguese and English; language selector persisted per session via Django `LocaleMiddleware` |

---

## Authentication and Access Control (RBAC)

### Authentication methods

| Method | Backend | Notes |
|--------|---------|-------|
| **Keycloak OIDC** (primary) | `MatrixOIDCBackend` | Authenticates via `preferred_username`; does NOT create users automatically — the user must be pre-registered in Matrix |
| **Local Django** (fallback) | `ModelBackend` | Username and password managed via Django admin |

**OIDC session:** token auto-renewal every 900 s (15 min). Total session expiry: 1 hour.

### RBAC groups

Three Django groups control access to all endpoints:

| Group | Permissions |
|-------|-----------|
| **Administrator** | Full access: create/deactivate users, manage BUs, deactivate products, approve SBOMs, access archive and Hunting |
| **Operator** | Read + write: SBOM/RAUC/EXT4 upload, VEX declaration, HBOM management, add threats, update mitigations |
| **Viewer** | Read-only: dashboard, component/CVE views, CRA export |

**Business Unit isolation:** all queries are filtered by the logged-in user's BU; superusers have unrestricted access.

---

## API Endpoints

All endpoints require an authenticated session. Required roles are indicated below.

### SBOM

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| `POST` | `/sbom/upload/` | Operator | Upload SBOM file (CycloneDX) |
| `GET` | `/sbom/api/components/<product_id>/` | Viewer | Components + CVEs for a product |
| `GET` | `/sbom/api/cve/<cve_id>/` | Viewer | CVE details (NVD, CVSS, EPSS) |
| `GET` | `/sbom/api/bu-stats/` | Viewer | General BU statistics |
| `GET` | `/sbom/api/vex/<vuln_id>/` | Viewer | Current VEX statement |
| `POST` | `/sbom/api/vex/<vuln_id>/declare/` | Operator | Create or update VEX statement |
| `GET` | `/sbom/api/vex/export/<product_id>/` | Viewer | Export CycloneDX 1.5 with VEX (CRA) |
| `GET` | `/sbom/api/download/<product_id>/` | Viewer | Download original SBOM |
| `GET` | `/sbom/api/scan-status/<product_id>/` | Viewer | Pipeline status (polling) |
| `POST` | `/sbom/api/deactivate/<product_id>/` | Administrator | Deactivate product |
| `GET` | `/sbom/aprovacao/` | Administrator | SBOM approval page |
| `GET` | `/sbom/api/approval/` | Administrator | List SBOMs pending approval |
| `POST` | `/sbom/api/approval/<upload_id>/approve/` | Administrator | Approve SBOM |
| `POST` | `/sbom/api/approval/<upload_id>/reject/` | Administrator | Reject SBOM with reason |
| `GET` | `/sbom/csv/template/` | Operator | Download CSV template |
| `POST` | `/sbom/api/csv/parse/` | Operator | Preview CSV before saving |
| `POST` | `/sbom/api/csv/save/` | Operator | Save manual SBOM via CSV |

### Firmware (RAUC / EXT4)

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| `POST` | `/rootfs/upload/` | Operator | Upload RAUC bundle (.raucb) in chunks |
| `POST` | `/rootfs/upload-ext4/` | Operator | Upload EXT4 image (.ext4) in chunks |
| `GET` | `/rootfs/api/check-hash/` | Operator | Check for duplicate hash before upload |
| `POST` | `/rootfs/api/deactivate-by-product/<product_id>/` | Administrator | Deactivate all RootFS for a product |

### HBOM

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| `GET` | `/hbom/<sbom_id>/` | Viewer | Get or create HBOM for an SBOM |
| `POST` | `/hbom/<hbom_id>/components/` | Operator | Add hardware component |
| `PUT` | `/hbom/components/<id>/update/` | Operator | Update hardware component |
| `DELETE` | `/hbom/components/<id>/` | Administrator | Remove hardware component |
| `POST` | `/hbom/components/<id>/threats/` | Operator | Link EMB3D threats to component |
| `DELETE` | `/hbom/threats/<threat_id>/` | Operator | Remove threat from component |
| `PUT` | `/hbom/mitigations/<id>/` | Operator | Update mitigation status |
| `GET` | `/hbom/emb3d/properties/` | Viewer | EMB3D properties grouped by category |
| `GET` | `/hbom/emb3d/threats/` | Viewer | Threats for selected PIDs |
| `GET` | `/hbom/emb3d/mitigations/<id>/` | Viewer | Mitigation details (ref. IEC 62443) |

### Hunting

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| `GET` | `/hunting/` | Administrator | Vulnerability hunting page |
| `GET` | `/hunting/api/overview/` | Administrator | General stats + top CVEs + top components |
| `GET` | `/hunting/api/component/` | Administrator | Search components by name/PURL/version |
| `GET` | `/hunting/api/cve/` | Administrator | Search CVEs across all products |
| `GET` | `/hunting/api/purl/` | Administrator | Search by Package URL |

### Archive

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| `GET` | `/archive/` | Administrator | Deactivated products archive page |
| `GET` | `/archive/api/products/` | Administrator | List archived products |
| `GET` | `/archive/api/products/<id>/components/` | Administrator | Components of an archived product |
| `GET` | `/archive/api/products/<id>/export/` | Administrator | Export archived product data |
| `POST` | `/archive/api/products/<id>/delete/` | Administrator | Permanently delete product (cascade) |

### Users and BUs

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| `GET` | `/accounts/usuarios/` | Administrator | User management page |
| `GET` | `/accounts/api/users/` | Administrator | List users with roles |
| `POST` | `/accounts/api/users/create/` | Administrator | Create user |
| `PUT` | `/accounts/api/users/<id>/edit/` | Administrator | Edit name/email |
| `POST` | `/accounts/api/users/<id>/deactivate/` | Administrator | Deactivate user |
| `POST` | `/accounts/api/users/<id>/activate/` | Administrator | Reactivate user |
| `GET/POST` | `/organizations/api/bus/` | Administrator | List or create Business Units |
| `DELETE` | `/organizations/api/bus/<id>/` | Administrator | Remove Business Unit |

---

## Celery Tasks

**Broker:** Redis | **Backend:** Redis | **Timezone:** America/Sao_Paulo

### Scheduled (Celery Beat)

| Task | Schedule | Description |
|------|----------|-------------|
| `update_grype_db` | 02:00 daily | Updates the Grype vulnerability database |
| `daily_rescan_all` | 03:00 daily | Rescans all COMPLETED SBOMs (batches of 8, 30 s interval) |
| `daily_integrity_check` | 05:00 daily | Checks PostgreSQL ↔ Neo4j consistency; alerts recorded in MongoDB |

### On-demand

| Task | Queue | Trigger | Description |
|------|-------|---------|-------------|
| `process_sbom_task` | default | SBOM upload | Parses CycloneDX, extracts components, runs Grype, saves to PostgreSQL + Neo4j |
| `process_rauc_task` | rauc | RAUC upload | Extracts bundle, mounts EXT4 via `losetup -f --show`, generates SBOM via Syft, triggers `process_sbom_task` |
| `process_ext4_task` | rauc | EXT4 upload | Mounts image via `losetup -f --show`, reads `/etc/os-release`, generates SBOM via Syft, triggers `process_sbom_task` |
| `run_grype_scan` | default | Manual or scheduled rescan | Runs Grype, fetches EPSS/KEV, updates PostgreSQL |
| `run_ingestion_update` | default | After Grype scan | Syncs results to Neo4j, recalculates risk scores |

---

## SBOM Status Reference

### Upload Status (`SbomUpload.status`)

Each uploaded SBOM (CycloneDX JSON, CSV, RAUC, or EXT4) goes through a lifecycle tracked by the `status` field.

| Status | Label | Description |
|--------|-------|-------------|
| `PENDING` | Pendente | Upload received and queued; waiting for the Celery worker to begin processing |
| `PROCESSING` | Processando | Celery task is actively parsing components and ingesting into PostgreSQL + Neo4j |
| `COMPLETED` | Concluído | Pipeline finished; components, CVEs and Neo4j graph are up to date |
| `FAILED` | Falha | Processing error (duplicate detected for an active product, or unhandled exception); `error_message` field contains details |
| `VALIDATION` | Em Validação | Awaiting administrator approval — applies to **CSV manual uploads only** |
| `REJECTED` | Rejeitado | Rejected by an administrator; `rejection_reason` field contains the justification |

#### Status Transitions

**CycloneDX JSON / RAUC / EXT4 uploads:**

```
UPLOAD ──► PENDING ──► PROCESSING ──► COMPLETED
                                  └──► FAILED
```

**CSV manual uploads:**

```
UPLOAD ──► VALIDATION ──► [Admin Approve] ──► PENDING ──► PROCESSING ──► COMPLETED
                      └──► [Admin Reject]  ──► REJECTED               └──► FAILED
```

> A `COMPLETED` upload automatically triggers the Grype vulnerability scan chain (`run_grype_scan` → `run_ingestion`).  
> `FAILED` records are retained for audit; the `error_message` field describes the failure reason.

---

### Vulnerability Status (`Vulnerability.status`)

| Status | Description |
|--------|-------------|
| `OPEN` | Default — vulnerability is active and unresolved |
| `RESOLVED` | Remediated (e.g., component updated to a patched version) |
| `ACCEPTED` | Risk accepted; no fix will be applied |

---

### VEX Statement Status (CISA-compliant)

VEX statements track exploitability per vulnerability, following the [CISA Minimum Requirements for VEX](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf). Each statement is auto-versioned on every update (`statement_version`, `doc_version`) and exported in CycloneDX 1.5 format via the CRA export endpoint.

| Status | Description | Required fields |
|--------|-------------|-----------------|
| `under_investigation` | Under Investigation | — |
| `affected` | Affected — product is vulnerable | `action_statement` (mandatory) |
| `not_affected` | Not Affected | `justification` **or** `impact_statement` (at least one mandatory) |
| `fixed` | Vulnerability has been fixed | — |

#### VEX Justifications (when status is `not_affected`)

| Justification | Description |
|---------------|-------------|
| `component_not_present` | Component Not Present |
| `vulnerable_code_not_present` | Vulnerable Code Not Present |
| `vulnerable_code_not_in_execute_path` | Vulnerable Code Not in Execute Path |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Vulnerable Code Cannot Be Controlled by Adversary |
| `inline_mitigations_already_exist` | Inline Mitigations Already Exist |

---

## Installation

**Requirements:** Docker ≥ 24, Docker Compose ≥ 2.20, 4 GB RAM, 20 GB disk.

```bash
# 1. Clone the repository
git clone <repo-url> && cd matrix

# 2. Configure environment variables
cp .env.example .env   # fill in credentials

# 3. Start all containers
docker compose up -d

# 4. Run migrations
docker exec -it matrix-app python manage.py migrate

# 5. Create RBAC groups
docker exec -it matrix-app python manage.py setup_groups

# 6. Create superuser
docker exec -it matrix-app python manage.py createsuperuser
```

| Service | URL |
|---------|-----|
| Application | http://localhost:8000 |
| Django Admin | http://localhost:8000/admin |
| Neo4j Browser | http://localhost:7474 |

> **Note:** `matrix-worker-rauc` requires `privileged: true` in Docker to mount EXT4 images via loop device.

#### Loop device configuration (host)

The RAUC and EXT4 pipelines mount filesystem images using `losetup -f --show` (atomic loop device allocation) followed by `mount -t ext4`. The default Linux kernel limit is typically 8 loop devices, which is insufficient under concurrent worker load.

Run the following **on the host** before starting the stack:

```bash
# Apply immediately (no reboot required)
sudo modprobe loop max_loop=64

# Make permanent
echo "options loop max_loop=64" | sudo tee /etc/modprobe.d/loop.conf
sudo update-initramfs -u
```

> With `--concurrency=4` on `matrix-worker-rauc`, a minimum of 8 free loop devices is recommended. 64 provides ample headroom.

### User management via CLI

```bash
# Create RBAC groups (Administrator, Operator, Viewer)
python manage.py setup_groups

# Assign a role to a user
python manage.py setup_groups --usuario joao --perfil Operator

# List users and roles
python manage.py setup_groups --listar
```

---

## Environment Variables

```env
# Django
SECRET_KEY=<random 50-character string>
DEBUG=False

# PostgreSQL
POSTGRES_DB=matrix
POSTGRES_USER=matrix
POSTGRES_PASSWORD=<password>
DATABASE_URL=postgres://matrix:<password>@matrix-db:5432/matrix

# Neo4j
NEO4J_USER=neo4j
NEO4J_PASSWORD=<password>
NEO4J_URI=bolt://neo4j:7687

# Redis
REDIS_PASSWORD=<password>
CELERY_BROKER_URL=redis://:${REDIS_PASSWORD}@redis:6379/0

# MongoDB
MONGO_USER=matrix_mongo
MONGO_PASSWORD=<password>
MONGODB_URI=mongodb://matrix_mongo:<password>@mongodb:27017/
MONGODB_DB=matrix_logs

# Keycloak OIDC
OIDC_RP_CLIENT_ID=matrix-sbom
OIDC_RP_CLIENT_SECRET=<client-secret>
OIDC_OP_BASE_URL=https://<keycloak-host>/realms/<realm>
```

---

## Project Structure

```
matrix/
├── app/
│   ├── config/
│   │   ├── settings.py          # Django settings (DB, Celery, OIDC, axes, i18n)
│   │   └── urls.py              # Root URL routing (includes i18n set_language)
│   ├── apps/
│   │   ├── accounts/            # Auth (OIDC + local), RBAC decorators, user management
│   │   ├── organizations/       # BusinessUnit, Product, UserBUMembership
│   │   ├── sbom/                # Component, SbomUpload, Vulnerability, VexStatement
│   │   ├── hbom/                # HbomUpload, HardwareComponent, EMB3D engine
│   │   ├── rootfs/              # RootFS, ScanLog, RAUC/EXT4 upload views
│   │   ├── vulnerabilities/     # Vulnerability (RootFS scope), RiskConfig
│   │   ├── hunting/             # Vulnerability hunting module
│   │   └── archive/             # Historical product archive
│   ├── core/
│   │   ├── celery.py            # Celery app configuration
│   │   └── mongo.py             # Centralized logging: log_audit, log_task, log_error
│   ├── locale/
│   │   ├── en/LC_MESSAGES/      # English translations (django.po / django.mo)
│   │   └── pt_BR/LC_MESSAGES/   # Portuguese translations (django.po / django.mo)
│   ├── tasks/
│   │   ├── sbom_tasks.py        # process_sbom_task (CycloneDX parse + Neo4j)
│   │   ├── scan_tasks.py        # run_grype_scan + run_ingestion_update
│   │   ├── rauc_tasks.py        # process_rauc_task (unsquashfs + losetup + Syft + pipeline)
│   │   ├── ext4_tasks.py        # process_ext4_task (losetup + Syft + pipeline)
│   │   └── scheduled_tasks.py   # update_grype_db, daily_rescan_all, integrity_check
│   ├── templates/               # Django templates (dashboard, signup, approval, archive)
│   └── static/
│       └── emb3d/
│           └── emb3d-stix-2.0.1.json   # MITRE EMB3D dataset (STIX 2.1)
├── docker/
│   └── app/Dockerfile
├── docker-compose.yml
└── .env
```

---

## Internationalization (i18n)

The interface supports **Portuguese (pt-BR)** and **English (en)**. Language selection is available on every page via a PT / EN toggle in the header and persists for the duration of the session.

**Implementation:**
- Django `LocaleMiddleware` + `USE_I18N = True`
- All interface strings wrapped in `{% trans "..." %}` template tags
- Translation catalogs compiled to binary `.mo` files via `msgfmt`
- Language switching via Django's built-in `set_language` view (POST, CSRF-protected)

**To recompile translations after editing `.po` files:**

```bash
cd matrix/app
msgfmt locale/en/LC_MESSAGES/django.po    -o locale/en/LC_MESSAGES/django.mo
msgfmt locale/pt_BR/LC_MESSAGES/django.po -o locale/pt_BR/LC_MESSAGES/django.mo
```

---

## Security

| Control | Implementation |
|---------|---------------|
| Password hashing | Argon2id (primary), PBKDF2 (fallback) |
| CSRF protection | Django token on all forms and AJAX calls |
| Session | `SameSite=Lax`, expires on browser close, 1-hour TTL |
| Brute-force protection | django-axes: 5 failures → 1-hour lockout (per user + IP) |
| OIDC | No automatic user creation; user must be pre-registered |
| RBAC | `@administrador_required` / `@operador_required` decorators on all sensitive views |
| Multi-tenant isolation | All queries filtered by the logged-in user's `business_unit` |
| Upload security | UUID as internal filename; path validated with `realpath()` + `startswith(MEDIA_ROOT)` |
| Cypher injection | 100% parameterized queries (`$param`); no f-strings with external data in Cypher |
| SBOM deduplication | SHA-256 computed server-side before processing; identical uploads for active products are rejected |
| Audit trail | MongoDB: every critical action (VEX, upload, deactivation, download, login) recorded with user + IP |
| Neo4j | Port 7687 restricted to `matrix_net`; not exposed to the host |
| Redis | Password required via `REDIS_PASSWORD` |

---

## Risk Score

```
score = CVSS × EPSS × exploit_multiplier × ransomware_multiplier

where:
  CVSS                  = base CVSS score (0–10)
  EPSS                  = exploitation probability (0–1, EPSS)
  exploit_multiplier    = 2.0 if CVE is a known exploited vulnerability (CISA KEV), else 1.0
  ransomware_multiplier = 1.5 if CVE is used in ransomware, else 1.0
```

| Level | Score | Color |
|-------|-------|-------|
| Critical | ≥ 50.0 | Red |
| High | ≥ 20.0 | Orange |
| Medium | ≥ 5.0 | Yellow |
| Low | ≥ 0.1 | Blue |
| Minimal | < 0.1 | Gray |
