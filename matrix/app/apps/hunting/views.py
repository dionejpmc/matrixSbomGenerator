"""
apps/hunting/views.py

Vulnerability Hunting — views e APIs
"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Q

from apps.sbom.models import Component, Vulnerability
from apps.organizations.models import Product, UserBUMembership
from apps.accounts.permissions import hunting_required


def _get_bu_filter(user):
    """
    Q() para filtrar Vulnerability pelo escopo do usuário.
    Sempre exclui produtos inativos.
    """
    if user.is_superuser or user.is_staff:
        return Q(component__product__active=True)
    membership = UserBUMembership.objects.filter(user=user).first()
    if not membership:
        return Q(pk__in=[])
    return Q(
        component__product__business_unit=membership.business_unit,
        component__product__active=True,
    )


def _get_product_bu_filter(user):
    """
    Q() para filtrar Product pelo escopo do usuário.
    Sempre exclui produtos inativos.
    Usar em querysets de Product diretamente.
    """
    if user.is_superuser or user.is_staff:
        return Q(active=True)
    membership = UserBUMembership.objects.filter(user=user).first()
    if not membership:
        return Q(pk__in=[])
    return Q(business_unit=membership.business_unit, active=True)


def _get_component_bu_filter(user):
    """
    Q() para filtrar Component pelo escopo do usuário.
    Sempre exclui produtos inativos.
    Usar em querysets de Component diretamente.
    """
    if user.is_superuser or user.is_staff:
        return Q(product__active=True)
    membership = UserBUMembership.objects.filter(user=user).first()
    if not membership:
        return Q(pk__in=[])
    return Q(
        product__business_unit=membership.business_unit,
        product__active=True,
    )


# ─────────────────────────────────────────────────────────────
# PAGE VIEW
# ─────────────────────────────────────────────────────────────

@login_required
@hunting_required
def hunting_view(request):
    return render(request, 'usuarios/vulnerability_hunting.html')


# ─────────────────────────────────────────────────────────────
# API: OVERVIEW (stats + top CVEs + top componentes)
# ─────────────────────────────────────────────────────────────

@login_required
@hunting_required
def api_overview(request):
    bu_q = _get_bu_filter(request.user)

    vulns = Vulnerability.objects.filter(bu_q)

    total_vulns = vulns.count()
    # kev_count and ransomware_count calculated below after deduplication by CVE

    unique_components = (
        Component.objects
        .filter(_get_component_bu_filter(request.user))
        .values('name', 'version')
        .distinct()
        .count()
    )

    # Top 10 CVEs mais recorrentes (por nº de componentes afetados)
    top_cves_qs = (
        vulns
        .values('cve_id', 'severity', 'known_exploited', 'known_ransomware')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    top_cves = [
        {
            'cve_id': v['cve_id'],
            'severity': v['severity'],
            'known_exploited': v['known_exploited'],
            'known_ransomware': v['known_ransomware'],
            'count': v['count'],
        }
        for v in top_cves_qs
    ]

    # Top 10 components with the most critical/high CVEs
    top_components_qs = (
        Component.objects
        .filter(_get_component_bu_filter(request.user))
        .annotate(
            total=Count('vulnerabilities'),
            critical=Count('vulnerabilities', filter=Q(vulnerabilities__severity='CRITICAL')),
            high=Count('vulnerabilities', filter=Q(vulnerabilities__severity='HIGH')),
        )
        .filter(total__gt=0)
        .order_by('-critical', '-high', '-total')[:10]
    )
    top_components = [
        {
            'name': c.name,
            'version': c.version,
            'total': c.total,
            'critical': c.critical,
            'high': c.high,
        }
        for c in top_components_qs
    ]

    # Lista completa de KEV para modal — deduplica por CVE ID, acumula componentes
    kev_qs = (
        vulns.filter(known_exploited=True)
        .select_related('component', 'component__product')
        .order_by('-cvss_score')
    )
    kev_seen = {}
    for v in kev_qs:
        if v.cve_id not in kev_seen:
            kev_seen[v.cve_id] = {
                'cve_id': v.cve_id,
                'severity': v.severity,
                'cvss_score': float(v.cvss_score) if v.cvss_score else None,
                'epss_score': float(v.epss_score) if v.epss_score is not None else None,
                'known_exploited': True,
                'known_ransomware': v.known_ransomware,
                'description': v.description,
                'component_name': v.component.name,
                'component_version': v.component.version or '',
                'occurrences': 1,
                'components': [{
                    'name': v.component.name,
                    'version': v.component.version or '',
                    'product': v.component.product.name,
                }],
            }
        else:
            kev_seen[v.cve_id]['occurrences'] += 1
            kev_seen[v.cve_id]['components'].append({
                'name': v.component.name,
                'version': v.component.version or '',
                'product': v.component.product.name,
            })
    kev_list = list(kev_seen.values())
    kev_count = len(kev_list)

    # Lista completa de Ransomware para modal — deduplica por CVE ID, acumula componentes
    ran_qs = (
        vulns.filter(known_ransomware=True)
        .select_related('component', 'component__product')
        .order_by('-cvss_score')
    )
    ran_seen = {}
    for v in ran_qs:
        if v.cve_id not in ran_seen:
            ran_seen[v.cve_id] = {
                'cve_id': v.cve_id,
                'severity': v.severity,
                'cvss_score': float(v.cvss_score) if v.cvss_score else None,
                'epss_score': float(v.epss_score) if v.epss_score is not None else None,
                'known_exploited': v.known_exploited,
                'known_ransomware': True,
                'description': v.description,
                'component_name': v.component.name,
                'component_version': v.component.version or '',
                'occurrences': 1,
                'components': [{
                    'name': v.component.name,
                    'version': v.component.version or '',
                    'product': v.component.product.name,
                }],
            }
        else:
            ran_seen[v.cve_id]['occurrences'] += 1
            ran_seen[v.cve_id]['components'].append({
                'name': v.component.name,
                'version': v.component.version or '',
                'product': v.component.product.name,
            })
    ransomware_list = list(ran_seen.values())
    ransomware_count = len(ransomware_list)

    return JsonResponse({
        'total_vulns': total_vulns,
        'kev_count': kev_count,
        'ransomware_count': ransomware_count,
        'unique_components': unique_components,
        'top_cves': top_cves,
        'top_components': top_components,
        'kev_list': kev_list,
        'ransomware_list': ransomware_list,
    })


# ─────────────────────────────────────────────────────────────
# API: SEARCH BY COMPONENT
# ─────────────────────────────────────────────────────────────

@login_required
@hunting_required
def api_search_component(request):
    name    = request.GET.get('name', '').strip()
    version = request.GET.get('version', '').strip()

    if not name:
        return JsonResponse({'error': 'name is required'}, status=400)

    comp_bu_q = _get_component_bu_filter(request.user)

    # Components matching the name (and optional version)
    comp_qs = Component.objects.filter(
        comp_bu_q,
        name__icontains=name,
    )
    if version:
        comp_qs = comp_qs.filter(version__icontains=version)

    comp_qs = comp_qs.select_related('product', 'product__business_unit').prefetch_related('vulnerabilities')

    # Products that contain this component
    products_seen = {}
    all_vulns = {}

    for comp in comp_qs:
        p = comp.product
        if p.id not in products_seen:
            products_seen[p.id] = {
                'id': p.id,
                'name': p.name,
                'version': p.version or '',
                'business_unit': p.business_unit.name if p.business_unit else '—',
            }
        for v in comp.vulnerabilities.all():
            if v.cve_id not in all_vulns:
                all_vulns[v.cve_id] = {
                    'cve_id': v.cve_id,
                    'severity': v.severity,
                    'description': v.description,
                    'cvss_score': float(v.cvss_score) if v.cvss_score else None,
                    'epss_score': float(v.epss_score) if v.epss_score is not None else None,
                    'known_exploited': v.known_exploited,
                    'known_ransomware': v.known_ransomware,
                    'status': v.status,
                }

    # Sort vulnerabilities by severity
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'NEGLIGIBLE': 4, 'UNKNOWN': 5}
    vulns_list = sorted(all_vulns.values(), key=lambda x: sev_order.get(x['severity'], 9))

    # Blast radius
    affected_products = len(products_seen)
    sev_breakdown = {}
    for v in vulns_list:
        s = v['severity']
        sev_breakdown[s] = sev_breakdown.get(s, 0) + 1

    blast = {
        'summary': f"'{name}' is present in {affected_products} product(s) in the BU",
        'detail': f"{len(vulns_list)} unique CVEs associated with this component",
        'affected_products': affected_products,
        'severity_breakdown': sev_breakdown,
    }

    # Timeline: when each CVE entered the inventory (by SBOM upload date)
    from apps.sbom.models import SbomUpload
    from django.db.models.functions import TruncMonth

    timeline_qs = (
        SbomUpload.objects
        .filter(
            product__in=[p['id'] for p in products_seen.values()],
            status='COMPLETED',
        )
        .annotate(month=TruncMonth('uploaded_at'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )
    timeline = [
        {'date': t['month'].strftime('%b/%y'), 'count': t['count']}
        for t in timeline_qs if t['month']
    ]

    return JsonResponse({
        'products': list(products_seen.values()),
        'vulnerabilities': vulns_list,
        'blast': blast,
        'timeline': timeline,
    })


# ─────────────────────────────────────────────────────────────
# API: SEARCH BY CVE
# ─────────────────────────────────────────────────────────────

@login_required
@hunting_required
def api_search_cve(request):
    cve_id = request.GET.get('cve_id', '').strip()

    if not cve_id:
        return JsonResponse({'error': 'cve_id obrigatório'}, status=400)

    bu_q = _get_bu_filter(request.user)

    # Busca parcial — icontains funciona para "CVE-2022", "44228", "log4shell" etc.
    vulns = Vulnerability.objects.filter(
        bu_q, cve_id__icontains=cve_id
    ).select_related(
        'component', 'component__product', 'component__product__business_unit'
    ).order_by('cve_id')

    if not vulns.exists():
        return JsonResponse({
            'cve_id': cve_id,
            'severity': 'UNKNOWN',
            'description': None,
            'cvss_score': None,
            'epss_score': None,
            'known_exploited': False,
            'known_ransomware': False,
            'affected': [],
            'blast': None,
            'timeline': [],
            'multiple': [],
        })

    # Group by CVE ID (partial search may return multiple CVEs)
    cve_groups = {}
    for v in vulns:
        if v.cve_id not in cve_groups:
            cve_groups[v.cve_id] = {
                'cve_id': v.cve_id,
                'severity': v.severity,
                'description': v.description,
                'cvss_score': float(v.cvss_score) if v.cvss_score else None,
                'epss_score': float(v.epss_score) if v.epss_score is not None else None,
                'known_exploited': v.known_exploited,
                'known_ransomware': v.known_ransomware,
                'affected': [],
                'products': set(),
            }
        c = v.component
        p = c.product
        cve_groups[v.cve_id]['affected'].append({
            'component_id': c.id,
            'component_name': c.name,
            'component_version': c.version or '',
            'product_name': p.name,
            'product_version': p.version or '',
            'business_unit': p.business_unit.name if p.business_unit else '—',
        })
        cve_groups[v.cve_id]['products'].add(p.id)

    # If the search returned multiple CVEs, send a summary list + details of the first one
    multiple = []
    all_products_seen = set()
    sev_breakdown_total = {}

    for cid, cdata in cve_groups.items():
        multiple.append({
            'cve_id': cid,
            'severity': cdata['severity'],
            'known_exploited': cdata['known_exploited'],
            'known_ransomware': cdata['known_ransomware'],
            'affected_count': len(cdata['affected']),
            'product_count': len(cdata['products']),
        })
        all_products_seen.update(cdata['products'])
        s = cdata['severity']
        sev_breakdown_total[s] = sev_breakdown_total.get(s, 0) + len(cdata['affected'])

    is_partial = len(cve_groups) > 1

    # Details of the first (or only) CVE
    first_key = list(cve_groups.keys())[0]
    first = cve_groups[first_key]
    products_seen = first['products']

    # Blast radius: aggregated for partial search, individual for exact CVE
    if is_partial:
        blast = {
            'summary': f"{len(cve_groups)} CVEs found affect {len(all_products_seen)} product(s) in the BU",
            'detail': f"Term '{cve_id}' — select a CVE below to see individual details",
            'affected_products': len(all_products_seen),
            'severity_breakdown': sev_breakdown_total,
        }
    else:
        blast = {
            'summary': f"'{first_key}' affects {len(products_seen)} product(s) in the BU",
            'detail': f"Present in {len(first['affected'])} component(s) in total",
            'affected_products': len(products_seen),
            'severity_breakdown': {first['severity']: len(first['affected'])},
        }

    from apps.sbom.models import SbomUpload
    from django.db.models.functions import TruncMonth

    timeline_qs = (
        SbomUpload.objects
        .filter(product__in=list(products_seen), status='COMPLETED')
        .annotate(month=TruncMonth('uploaded_at'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )
    timeline = [
        {'date': t['month'].strftime('%b/%y'), 'count': t['count']}
        for t in timeline_qs if t['month']
    ]

    return JsonResponse({
        'cve_id': first['cve_id'],
        'severity': first['severity'],
        'description': first['description'],
        'cvss_score': first['cvss_score'],
        'epss_score': first['epss_score'],
        'known_exploited': first['known_exploited'],
        'known_ransomware': first['known_ransomware'],
        'affected': first['affected'],
        'blast': blast,
        'timeline': timeline,
        'multiple': multiple,  # full list when a partial search returns multiple CVEs
    })


# ─────────────────────────────────────────────────────────────
# API: SEARCH BY PURL
# ─────────────────────────────────────────────────────────────

@login_required
@hunting_required
def api_search_purl(request):
    purl = request.GET.get('purl', '').strip()

    if not purl:
        return JsonResponse({'error': 'purl obrigatório'}, status=400)

    comps = (
        Component.objects
        .filter(_get_component_bu_filter(request.user), purl__icontains=purl)
        .select_related('product', 'product__business_unit')
        .prefetch_related('vulnerabilities')
        .order_by('purl', 'version')
    )

    # Agrupa por PURL exato
    groups = {}
    for c in comps:
        key = c.purl or f"{c.name}@{c.version}"
        if key not in groups:
            groups[key] = {
                'purl': key,
                'products': [],
                'vuln_count': 0,
            }
        p = c.product
        groups[key]['products'].append({
            'id': p.id,
            'name': p.name,
            'version': p.version or '',
        })
        groups[key]['vuln_count'] += c.vulnerabilities.count()

    return JsonResponse(list(groups.values()), safe=False)