import json
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from .models import UserBUMembership, BusinessUnit


@login_required
def api_bu_list_create(request):
    """Lists all BUs (GET) or creates a new one (POST) — superuser only."""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Access denied'}, status=403)

    if request.method == 'GET':
        bus = BusinessUnit.objects.all().order_by('name')
        result = [
            {
                'id': bu.id,
                'name': bu.name,
                'user_count': UserBUMembership.objects.filter(business_unit=bu).count(),
                'product_count': bu.products.filter(active=True).count(),
            }
            for bu in bus
        ]
        return JsonResponse({'bus': result})

    if request.method == 'POST':
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        if not name:
            return JsonResponse({'error': 'Name is required'}, status=400)
        if BusinessUnit.objects.filter(name__iexact=name).exists():
            return JsonResponse({'error': f'BU "{name}" already exists'}, status=400)
        bu = BusinessUnit.objects.create(name=name)
        return JsonResponse({'id': bu.id, 'name': bu.name, 'user_count': 0, 'product_count': 0}, status=201)

    return JsonResponse({'error': 'Method not allowed'}, status=405)


@login_required
@require_http_methods(['DELETE'])
def api_bu_delete(request, bu_id):
    """Deletes a BU — superuser only."""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Access denied'}, status=403)

    bu = BusinessUnit.objects.filter(id=bu_id).first()
    if not bu:
        return JsonResponse({'error': 'BU not found'}, status=404)

    user_count = UserBUMembership.objects.filter(business_unit=bu).count()
    product_count = bu.products.filter(active=True).count()

    if user_count > 0 or product_count > 0:
        return JsonResponse({
            'error': f'BU has {user_count} user(s) and {product_count} active product(s). Remove them before deleting.'
        }, status=400)

    bu.delete()
    return JsonResponse({'status': 'deleted'})