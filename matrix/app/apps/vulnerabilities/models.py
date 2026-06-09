from django.db import models
from apps.rootfs.models import RootFS

class Vulnerability(models.Model):
    # Severity levels following the CVSS standard
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Crítico'),
        ('HIGH', 'Alto'),
        ('MEDIUM', 'Médio'),
        ('LOW', 'Baixo'),
        ('UNKNOWN', 'Desconhecido'),
    ]

    rootfs = models.ForeignKey(RootFS, on_delete=models.CASCADE, related_name='vulnerabilities')
    cve_id = models.CharField(max_length=50) # Ex: CVE-2023-1234
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(null=True, blank=True)
    package_name = models.CharField(max_length=255)
    package_version = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    
    # Triage control (VEX / context)
    is_false_positive = models.BooleanField(default=False)
    fix_status = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.cve_id} - {self.package_name}"

    class Meta:
        verbose_name_plural = "Vulnerabilities"


class RiskConfig(models.Model):
    """
    Configurable weights and multipliers used in the Risk Score calculation.
    Values can be adjusted via the admin panel without code changes.

    Initial records (created via migration or manage.py shell):
        weight_cvss                = 1.0  — CVSS score weight
        weight_epss                = 1.0  — EPSS score weight
        multiplier_known_exploited = 2.0  — multiplier if exploit is known
        multiplier_known_ransomware = 1.5 — multiplier if used in ransomware
        threshold_low              = 0.1  — lower bound for Low risk
        threshold_medium           = 5.0  — lower bound for Medium risk
        threshold_high             = 20.0 — lower bound for High risk
        threshold_critical         = 50.0 — lower bound for Critical risk
    """

    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Parameter name. E.g.: weight_cvss, multiplier_known_exploited"
    )
    value = models.FloatField(
        help_text="Numeric value of the parameter"
    )
    description = models.TextField(
        blank=True,
        help_text="Description of what this parameter controls"
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name}: {self.value}"

    class Meta:
        verbose_name = "Risk Configuration"
        verbose_name_plural = "Risk Configurations"