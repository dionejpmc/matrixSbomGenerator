# matrix/app/usuarios/views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from apps.organizations.models import Product, UserBUMembership
from apps.accounts.permissions import is_operador
from django.db.models import Count

@login_required
def dashboard(request):
    membership = UserBUMembership.objects.filter(user=request.user).first()
    
    products_qs = Product.objects.none()
    current_bu = "Nenhuma Unidade Vinculada"
    if membership:
        products_qs = Product.objects.filter(
            business_unit=membership.business_unit
        ).select_related(
            'business_unit', 'created_by'
        ).annotate(
            total_components=Count('components')
        ).exclude(active=False).order_by('-created_at')
        
        current_bu = membership.business_unit.name

    paginator = Paginator(products_qs, 10)  # 10 per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    context = {
        'products': page_obj,
        'page_obj': page_obj,
        'paginator': paginator,
        'current_bu': current_bu,
        'can_upload': is_operador(request.user),
    }
    return render(request, 'usuarios/dashboard.html', context)