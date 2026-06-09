from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.shortcuts import get_object_or_404
from django.utils import timezone
import json

from apps.sbom.models import SbomUpload
from .models import HbomUpload, HardwareComponent, ComponentThreat, ThreatMitigation
from .models import COMPONENT_TYPE_CHOICES, INTERFACE_CHOICES
from .emb3d import load_emb3d, get_threats_for_pids, get_properties_by_category
from apps.accounts.permissions import administrador_required, operador_required
from core.mongo import log_audit


# ─────────────────────────────────────────────
# HBOM
# ─────────────────────────────────────────────

@login_required
def api_hbom_get_or_create(request, sbom_id):
    """Returns the existing HBOM or creates an empty one for the given SBOM."""
    sbom = get_object_or_404(SbomUpload, id=sbom_id)
    hbom, _ = HbomUpload.objects.get_or_create(sbom=sbom)

    components = []
    for comp in hbom.components.prefetch_related('threats__mitigations').all():
        threats = []
        for t in comp.threats.all():
            threats.append({
                'id': str(t.id),
                'threat_id': t.threat_id,
                'threat_name': t.threat_name,
                'triggered_by_pids': t.triggered_by_pids,
                'mitigations': [
                    {
                        'id': str(m.id),
                        'mitigation_id': m.mitigation_id,
                        'mitigation_name': m.mitigation_name,
                        'status': m.status,
                        'notes': m.notes,
                        'resolved_at': m.resolved_at.isoformat() if m.resolved_at else None,
                    }
                    for m in t.mitigations.all()
                ]
            })
        components.append({
            'id': str(comp.id),
            'name': comp.name,
            'manufacturer': comp.manufacturer,
            'type': comp.type,
            'version': comp.version,
            'interfaces': comp.interfaces,
            'secure_boot': comp.secure_boot,
            'firmware_signed': comp.firmware_signed,
            'encrypted_storage': comp.encrypted_storage,
            'debug_ports_disabled': comp.debug_ports_disabled,
            'notes': comp.notes,
            'threats': threats,
        })

    return JsonResponse({
        'hbom_id': str(hbom.id),
        'sbom_id': str(sbom.id),
        'product_name': sbom.product_name,
        'components': components,
        'component_types': COMPONENT_TYPE_CHOICES,
        'interface_choices': INTERFACE_CHOICES,
    })


@login_required
@operador_required
@require_http_methods(['POST'])
def api_hbom_add_component(request, hbom_id):
    """Adds a hardware component to the HBOM."""
    hbom = get_object_or_404(HbomUpload, id=hbom_id)
    data = json.loads(request.body)

    comp = HardwareComponent.objects.create(
        hbom=hbom,
        name=data.get('name', ''),
        manufacturer=data.get('manufacturer', ''),
        type=data.get('type', 'OTHER'),
        version=data.get('version', ''),
        interfaces=data.get('interfaces', []),
        secure_boot=data.get('secure_boot', False),
        firmware_signed=data.get('firmware_signed', False),
        encrypted_storage=data.get('encrypted_storage', False),
        debug_ports_disabled=data.get('debug_ports_disabled', False),
        notes=data.get('notes', ''),
    )

    log_audit(request.user, 'HBOM_ADD_COMPONENT',
              hbom_id=hbom_id,
              component_id=str(comp.id),
              component_name=comp.name,
              component_type=comp.type)

    return JsonResponse({'id': str(comp.id), 'name': comp.name}, status=201)


@login_required
@operador_required
@require_http_methods(['PUT'])
def api_hbom_update_component(request, component_id):
    """Updates a hardware component in the HBOM."""
    comp = get_object_or_404(HardwareComponent, id=component_id)
    data = json.loads(request.body)

    for field in ['name', 'manufacturer', 'type', 'version', 'interfaces',
                  'secure_boot', 'firmware_signed', 'encrypted_storage',
                  'debug_ports_disabled', 'notes']:
        if field in data:
            setattr(comp, field, data[field])
    comp.save()

    log_audit(request.user, 'HBOM_UPDATE_COMPONENT',
              component_id=component_id,
              component_name=comp.name,
              fields_updated=[f for f in data.keys()])

    return JsonResponse({'updated': True})


@login_required
@administrador_required
@require_http_methods(['DELETE'])
def api_hbom_delete_component(request, component_id):
    """Remove um componente do HBOM."""
    comp = get_object_or_404(HardwareComponent, id=component_id)
    log_audit(request.user, 'HBOM_DELETE_COMPONENT',
              component_id=component_id,
              component_name=comp.name)
    comp.delete()
    return JsonResponse({'deleted': True})


# ─────────────────────────────────────────────
# EMB3D — Properties (PIDs)
# ─────────────────────────────────────────────

@login_required
def api_emb3d_properties(request):
    """
    Retorna todas as PIDs agrupadas por categoria com sub-propriedades aninhadas.
    Usado para renderizar o checklist de seleção de propriedades.
    """
    categories = get_properties_by_category()
    return JsonResponse({'categories': categories})


@login_required
def api_emb3d_threats_for_pids(request):
    """
    Recebe uma lista de PIDs via GET (?pid=PID-11&pid=PID-15)
    e retorna as threats aplicáveis com suas mitigações.
    """
    pid_list = request.GET.getlist('pid')
    if not pid_list:
        return JsonResponse({'threats': []})

    threats = get_threats_for_pids(pid_list)
    return JsonResponse({'threats': threats, 'pids': pid_list})


# ─────────────────────────────────────────────
# ComponentThreat — map threats to a component
# ─────────────────────────────────────────────

@login_required
@operador_required
@require_http_methods(['POST'])
def api_component_add_threats(request, component_id):
    """
    Associates selected threats with a component.
    Automatically creates all corresponding mitigations with status PENDING.

    Body: {
        "pids": ["PID-11", "PID-15"],
        "threats": [
            { "tid": "TID-115", "name": "Firmware/Data Extraction..." }
        ]
    }
    """
    comp = get_object_or_404(HardwareComponent, id=component_id)
    data = json.loads(request.body)

    pids = data.get('pids', [])
    threats_data = data.get('threats', [])

    emb3d = load_emb3d()
    created = []

    for t in threats_data:
        tid = t.get('tid')
        if not tid:
            continue

        # Create or retrieve the threat
        comp_threat, threat_created = ComponentThreat.objects.get_or_create(
            component=comp,
            threat_id=tid,
            defaults={
                'threat_name': t.get('name', ''),
                'triggered_by_pids': pids,
            }
        )

        # Auto-create mitigations only when the threat was just created
        if threat_created:
            threat_full = emb3d['threats'].get(tid, {})
            for mit in threat_full.get('mitigations', []):
                ThreatMitigation.objects.get_or_create(
                    component_threat=comp_threat,
                    mitigation_id=mit['mid'],
                    defaults={
                        'mitigation_name': mit['name'],
                        'status': 'PENDING',
                    }
                )

        created.append(str(comp_threat.id))

    log_audit(request.user, 'HBOM_ADD_THREATS',
              component_id=component_id,
              component_name=comp.name,
              threats_added=[t.get('tid') for t in threats_data],
              pids=pids)

    return JsonResponse({'created': len(created), 'ids': created}, status=201)


@login_required
@administrador_required
@require_http_methods(['DELETE'])
def api_component_remove_threat(request, threat_id):
    """Removes a threat (and its mitigations in cascade) from a component."""
    threat = get_object_or_404(ComponentThreat, id=threat_id)
    log_audit(request.user, 'HBOM_REMOVE_THREAT',
              threat_id=threat_id,
              threat_name=threat.threat_name,
              component_name=threat.component.name)
    threat.delete()
    return JsonResponse({'deleted': True})


# ─────────────────────────────────────────────
# ThreatMitigation — update status
# ─────────────────────────────────────────────

@login_required
@operador_required
@require_http_methods(['PUT'])
def api_mitigation_update_status(request, mitigation_id):
    """
    Updates the status of a mitigation.

    Body: { "status": "RESOLVED", "notes": "Implemented in v2.1" }
    """
    mit = get_object_or_404(ThreatMitigation, id=mitigation_id)
    data = json.loads(request.body)
    old_status = mit.status

    new_status = data.get('status')
    if new_status and new_status in ['PENDING', 'RESOLVED', 'ACCEPTED']:
        mit.status = new_status
        if new_status == 'RESOLVED' and not mit.resolved_at:
            mit.resolved_at = timezone.now()
        elif new_status != 'RESOLVED':
            mit.resolved_at = None

    if 'notes' in data:
        mit.notes = data['notes']

    mit.save()

    log_audit(request.user, 'HBOM_UPDATE_MITIGATION',
              mitigation_id=mitigation_id,
              mitigation_name=mit.mitigation_name,
              old_status=old_status,
              new_status=mit.status,
              component=mit.component_threat.component.name,
              threat=mit.component_threat.threat_id)

    return JsonResponse({
        'updated': True,
        'status': mit.status,
        'resolved_at': mit.resolved_at.isoformat() if mit.resolved_at else None,
    })


@login_required
def api_emb3d_mitigation_detail(request, mitigation_id):
    """Returns full details of a mitigation by its MID (e.g. MID-057)."""
    from .emb3d import load_emb3d
    data = load_emb3d()
    mit = data['mitigations'].get(mitigation_id)
    if not mit:
        return JsonResponse({'error': 'não encontrado'}, status=404)
    return JsonResponse(mit)