from django.db import models
from apps.organizations.models import Product
import uuid
import hashlib
from django.utils import timezone  # <--- Adicione esta linha

class Component(models.Model):
    SCOPE_CHOICES = [
        ('third_party', 'Terceiros'),
        ('first_party', 'Primeira parte'),
    ]

    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='components')
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100)
    type = models.CharField(max_length=50, blank=True)
    purl = models.CharField(max_length=500, blank=True, null=True)
    cpe = models.CharField(max_length=500, blank=True, null=True)
    license = models.CharField(max_length=255, blank=True, null=True)

    # campos adicionais extraídos pelo scanner de código-fonte
    supplier = models.CharField(max_length=255, blank=True, null=True)
    copyright = models.CharField(max_length=500, blank=True, null=True)
    author = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    depends = models.TextField(blank=True, null=True)
    folder = models.CharField(max_length=1000, blank=True, null=True)
    scope = models.CharField(max_length=20, choices=SCOPE_CHOICES, default='third_party', blank=True)

    def __str__(self):
        return f"{self.name}@{self.version}"
    
def upload_to_uuid(instance, filename):
    ext = filename.split('.')[-1]
    now = timezone.now()
    date_path = now.strftime('%Y/%m/%d')
    return f'sboms/{date_path}/{instance.id}.{ext}'

class SbomUpload(models.Model):
    STATUS_CHOICES = [
        ('PENDING',    'Pendente'),
        ('PROCESSING', 'Processando'),
        ('COMPLETED',  'Concluído'),
        ('FAILED',     'Falha'),
        ('VALIDATION', 'Em Validação'),
        ('REJECTED',   'Rejeitado'),
    ]

    SOURCE_CHOICES = [
        ('upload', 'Upload SBOM'),
        ('rauc',   'RAUC Bundle'),
        ('csv',    'CSV Manual'),
    ]

    product_name = models.CharField(max_length=255)
    active = models.BooleanField(default=True)
    product = models.ForeignKey(
        'organizations.Product',
        on_delete=models.CASCADE,
        related_name='uploads',
        null=True,
        blank=True
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sbom_file = models.FileField(upload_to=upload_to_uuid, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default='upload')
    hashcode = models.CharField(max_length=64, editable=False, unique=False, null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='sbom_uploads',
    )
    reviewed_by = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='sbom_reviews',
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.sbom_file and not self.hashcode:
            self.hashcode = self.generate_hash()
        super().save(*args, **kwargs)

    def generate_hash(self):
        sha256_hash = hashlib.sha256()
        for chunk in self.sbom_file.chunks():
            sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def __str__(self):
        return f"{self.product_name} - {self.uploaded_at}"

class Vulnerability(models.Model):
    component = models.ForeignKey(Component, on_delete=models.CASCADE, related_name='vulnerabilities')
    cve_id = models.CharField(max_length=50) 
    severity = models.CharField(max_length=20) 
    description = models.TextField(null=True, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    status = models.CharField(max_length=50, default='OPEN') 
    epss_score = models.FloatField(null=True, blank=True)        # 0.0 a 1.0
    known_exploited = models.BooleanField(default=False)
    known_ransomware = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.cve_id} - {self.component.name}"
    


class VexStatement(models.Model):
    """
    Declaração VEX (Vulnerability Exploitability eXchange) conforme CISA MUST requirements.
    Referência: https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf
    """

    # ── Status CISA VEX ────────────────────────────────────────
    STATUS_CHOICES = [
        ('under_investigation', 'Under Investigation'),
        ('affected',            'Affected'),
        ('not_affected',        'Not Affected'),
        ('fixed',               'Fixed'),
    ]

    # ── CISA justifications (required when not_affected) ────────
    JUSTIFICATION_CHOICES = [
        ('component_not_present',                       'Component Not Present'),
        ('vulnerable_code_not_present',                 'Vulnerable Code Not Present'),
        ('vulnerable_code_not_in_execute_path',         'Vulnerable Code Not in Execute Path'),
        ('vulnerable_code_cannot_be_controlled_by_adversary', 'Vulnerable Code Cannot Be Controlled by Adversary'),
        ('inline_mitigations_already_exist',            'Inline Mitigations Already Exist'),
    ]

    # ── Identificadores ────────────────────────────────────────
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Link to the vulnerability
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name='vex_statements',
    )

    # ── Metadados do documento VEX (doc-level) ─────────────────
    doc_id = models.UUIDField(default=uuid.uuid4, editable=False)
    doc_version = models.PositiveIntegerField(default=1)
    doc_time_first_issued = models.DateTimeField(auto_now_add=True)
    doc_time_last_updated = models.DateTimeField(auto_now=True)

    # ── Autor ─────────────────────────────────────────────────
    author = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='vex_statements',
    )
    tooling = models.CharField(
        max_length=100,
        default='Matrix SBOM Monitor',
        editable=False,
    )

    # ── Statement metadata ─────────────────────────────────────
    statement_version = models.PositiveIntegerField(default=1)
    statement_time_first_issued = models.DateTimeField(auto_now_add=True)
    statement_time_last_updated = models.DateTimeField(auto_now=True)

    # ── Status VEX ────────────────────────────────────────────
    status = models.CharField(
        max_length=50,
        choices=STATUS_CHOICES,
        default='under_investigation',
    )

    # ── Justification (required if not_affected without impact_statement) ──
    justification = models.CharField(
        max_length=100,
        choices=JUSTIFICATION_CHOICES,
        null=True,
        blank=True,
    )

    # ── Impact statement (not_affected sem justification) ──────
    impact_statement = models.TextField(null=True, blank=True)

    # ── Action statement (required if affected) ──────────────────
    action_statement = models.TextField(null=True, blank=True)

    # ── Status notes (opcional) ───────────────────────────────
    status_notes = models.TextField(null=True, blank=True)

    class Meta:
        ordering = ['-statement_time_last_updated']
        verbose_name = 'VEX Statement'
        verbose_name_plural = 'VEX Statements'

    def save(self, *args, **kwargs):
        # Increment statement version on every update
        if self.pk:
            self.statement_version += 1
            self.doc_version += 1
        super().save(*args, **kwargs)

    def __str__(self):
        return f"VEX {self.vulnerability.cve_id} → {self.status}"

    def to_cyclonedx_vex(self):
        """Retorna o statement no formato CycloneDX VEX."""
        vuln = self.vulnerability
        comp = vuln.component
        product = comp.product

        statement = {
            'id': str(self.id),
            'source': {'name': 'NVD', 'url': f'https://nvd.nist.gov/vuln/detail/{vuln.cve_id}'},
            'ratings': [{'source': {'name': 'NVD'}, 'severity': vuln.severity.lower()}],
            'cwes': [],
            'description': vuln.description or '',
            'detail': self.status_notes or '',
            'analysis': {
                'state': self.status,
                'justification': self.justification or '',
                'response': [],
                'detail': self.action_statement or self.impact_statement or '',
            },
            'affects': [
                {
                    'ref': comp.purl or f'pkg:generic/{comp.name}@{comp.version}',
                    'versions': [{'version': comp.version, 'status': self.status}],
                }
            ],
        }
        return statement