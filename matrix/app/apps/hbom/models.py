import uuid
from django.db import models
from apps.sbom.models import SbomUpload

INTERFACE_CHOICES = [
    ('UART', 'UART'),
    ('JTAG', 'JTAG'),
    ('USB', 'USB'),
    ('SPI', 'SPI'),
    ('I2C', 'I2C'),
    ('CAN', 'CAN'),
    ('BLE', 'Bluetooth LE'),
    ('WIFI', 'Wi-Fi'),
    ('ETH', 'Ethernet'),
    ('NFC', 'NFC'),
    ('ZIGBEE', 'Zigbee'),
    ('LORA', 'LoRa'),
    ('GPIO', 'GPIO'),
    ('SDCARD', 'SD Card'),
    ('EMMC', 'eMMC/Flash'),
]

COMPONENT_TYPE_CHOICES = [
    ('CPU', 'Processador / SoC'),
    ('MCU', 'Microcontrolador'),
    ('BLUETOOTH', 'Bluetooth'),
    ('WIFI', 'Wi-Fi'),
    ('CELLULAR', 'Celular / GSM / LTE'),
    ('FLASH', 'Memória Flash'),
    ('RAM', 'Memória RAM'),
    ('CRYPTO', 'Criptografia / TPM / SE'),
    ('PMIC', 'Gerenciamento de energia'),
    ('SENSOR', 'Sensor'),
    ('GPS', 'GPS / GNSS'),
    ('DISPLAY', 'Display'),
    ('CAMERA', 'Câmera'),
    ('AUDIO', 'Áudio'),
    ('OTHER', 'Outro'),
]


class HbomUpload(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sbom = models.OneToOneField(
        SbomUpload,
        on_delete=models.CASCADE,
        related_name='hbom',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"HBOM → {self.sbom.product_name}"


class HardwareComponent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hbom = models.ForeignKey(
        HbomUpload,
        on_delete=models.CASCADE,
        related_name='components',
    )
    name = models.CharField(max_length=255)
    manufacturer = models.CharField(max_length=255)
    type = models.CharField(max_length=50, choices=COMPONENT_TYPE_CHOICES)
    version = models.CharField(max_length=100, blank=True)
    interfaces = models.JSONField(default=list, blank=True)
    secure_boot = models.BooleanField(default=False)
    firmware_signed = models.BooleanField(default=False)
    encrypted_storage = models.BooleanField(default=False)
    debug_ports_disabled = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.get_type_display()}) v{self.version}"


class ComponentThreat(models.Model):
    """
    EMB3D threat associated with a hardware component.
    Full data lives in the static JSON file — this model stores only the reference and a cached name.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    component = models.ForeignKey(
        HardwareComponent,
        on_delete=models.CASCADE,
        related_name='threats',
    )
    threat_id = models.CharField(max_length=20)     # e.g. TID-115
    threat_name = models.CharField(max_length=255)  # cached from the EMB3D JSON

    # PIDs that triggered this threat — traceability
    triggered_by_pids = models.JSONField(default=list)  # e.g. ["PID-15", "PID-14"]

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('component', 'threat_id')

    def __str__(self):
        return f"{self.threat_id} → {self.component.name}"


class ThreatMitigation(models.Model):
    """
    EMB3D mitigation with analyst-managed status.
    """
    STATUS_CHOICES = [
        ('PENDING', 'Pendente'),
        ('RESOLVED', 'Corrigida'),
        ('ACCEPTED', 'Risco Aceito'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    component_threat = models.ForeignKey(
        ComponentThreat,
        on_delete=models.CASCADE,
        related_name='mitigations',
    )
    mitigation_id = models.CharField(max_length=20)     # e.g. MID-057
    mitigation_name = models.CharField(max_length=255)  # cached from the EMB3D JSON

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    notes = models.TextField(blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('component_threat', 'mitigation_id')

    def __str__(self):
        return f"{self.mitigation_id} [{self.status}] → {self.component_threat.threat_id}"