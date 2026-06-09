"""
apps/hbom/emb3d.py

Utility for reading and parsing the EMB3D dataset (STIX 2.1).
The JSON is read once and cached in memory.
"""

import json
import os
from django.conf import settings

_cache = None


def _get_json_path():
    return os.path.join(settings.BASE_DIR, 'static', 'emb3d', 'emb3d-stix-2.0.1.json')


def load_emb3d():
    """Returns the parsed EMB3D dataset. Uses in-memory cache after the first read."""
    global _cache
    if _cache is None:
        path = _get_json_path()
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        _cache = _parse(data)
    return _cache


def reload_emb3d():
    """Forces a re-read of the JSON without restarting the server."""
    global _cache
    _cache = None
    return load_emb3d()


def _parse(data):
    objects = data['objects']
    by_id = {o['id']: o for o in objects}

    # --- Mitigations ---
    mitigations_by_stix = {}
    mitigations_index = {}
    for o in objects:
        if o['type'] == 'course-of-action':
            mid = o.get('x_mitre_emb3d_mitigation_id', '')
            entry = {
                'mid': mid,
                'name': o.get('name', ''),
                'description': o.get('description', ''),
                'references': o.get('x_mitre_emb3d_mitigation_references', ''),
                'iec_62443': o.get('x_mitre_emb3d_mitigation_IEC_62443_mappings', ''),
            }
            mitigations_by_stix[o['id']] = entry
            mitigations_index[mid] = entry

    # --- Threats ---
    threats_by_stix = {}
    threats_index = {}
    for o in objects:
        if o['type'] == 'vulnerability':
            tid = o.get('x_mitre_emb3d_threat_id', '')
            entry = {
                'tid': tid,
                'name': o.get('name', ''),
                'description': o.get('description', ''),
                'category': o.get('x_mitre_emb3d_threat_category', ''),
                'maturity': o.get('x_mitre_emb3d_threat_maturity', ''),
                'cves': o.get('x_mitre_emb3d_threat_CVEs', ''),
                'cwes': o.get('x_mitre_emb3d_threat_CWEs', ''),
                'evidence': o.get('x_mitre_emb3d_threat_evidence', ''),
                'mitigations': [],
            }
            threats_by_stix[o['id']] = entry
            threats_index[tid] = entry

    # Mitigations → Threats
    for o in objects:
        if o['type'] == 'relationship' and o['relationship_type'] == 'mitigates':
            threat = threats_by_stix.get(o['target_ref'])
            mitigation = mitigations_by_stix.get(o['source_ref'])
            if threat and mitigation:
                threat['mitigations'].append(mitigation)

    # --- Properties ---
    properties_by_stix = {}
    for o in objects:
        if o['type'] == 'x-mitre-emb3d-property':
            pid = o.get('x_mitre_emb3d_property_id', '')
            entry = {
                'pid': pid,
                'name': o.get('name', ''),
                'category': o.get('category', ''),
                'is_subproperty': o.get('is_subproperty', False),
                'parent_pid': None,
                'threats': [],
            }
            properties_by_stix[o['id']] = entry

    # Subproperty-of hierarchy
    for o in objects:
        if o['type'] == 'relationship' and o['relationship_type'] == 'subproperty-of':
            child = properties_by_stix.get(o['source_ref'])
            parent = properties_by_stix.get(o['target_ref'])
            if child and parent:
                child['parent_pid'] = parent['pid']

    # PIDs → Threats
    for o in objects:
        if o['type'] == 'relationship' and o['relationship_type'] == 'relates-to':
            prop = properties_by_stix.get(o['source_ref'])
            threat = threats_by_stix.get(o['target_ref'])
            if prop and threat:
                prop['threats'].append(threat)

    properties = sorted(
        properties_by_stix.values(),
        key=lambda p: _pid_sort_key(p['pid'])
    )

    return {
        'properties': properties,
        'threats': threats_index,
        'mitigations': mitigations_index,
    }


def _pid_sort_key(pid):
    try:
        return int(pid.replace('PID-', ''))
    except ValueError:
        return 9999


def get_threats_for_pids(pid_list):
    """
    Given a list of selected PIDs, returns all applicable threats
    without duplicates, including their mitigations.
    """
    data = load_emb3d()
    pid_set = set(pid_list)
    seen_tids = set()
    threats = []

    for prop in data['properties']:
        if prop['pid'] in pid_set:
            for threat in prop['threats']:
                if threat['tid'] not in seen_tids:
                    seen_tids.add(threat['tid'])
                    threats.append(threat)

    return sorted(threats, key=lambda t: t['tid'])


def get_properties_by_category():
    """
    Returns properties grouped by category with nested sub-properties.
    Used to render the property selection checklist on the frontend.
    """
    data = load_emb3d()
    categories = {}

    for prop in data['properties']:
        if prop['is_subproperty']:
            continue
        cat = prop['category']
        if cat not in categories:
            categories[cat] = []
        children = [
            p for p in data['properties']
            if p['is_subproperty'] and p['parent_pid'] == prop['pid']
        ]
        categories[cat].append({**prop, 'children': children})

    order = ['Hardware', 'System Software', 'Application Software', 'Networking']
    return {cat: categories.get(cat, []) for cat in order}