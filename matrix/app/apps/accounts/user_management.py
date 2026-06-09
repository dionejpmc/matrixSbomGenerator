"""
apps/accounts/user_management.py

Views for user management — administrators only.
Users are never deleted, only deactivated (is_active=False).
"""
import json
import logging
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.shortcuts import render

from apps.organizations.models import UserBUMembership, BusinessUnit
from apps.accounts.permissions import administrador_required
from core.mongo import log_audit, log_error

logger = logging.getLogger(__name__)

ROLE_TO_GROUP = {
    'admin':    'Administrador',
    'operator': 'Operador',
    'viewer':   'Visualizador',
}


@login_required
@administrador_required
def user_management_view(request):
    """User management page."""
    return render(request, 'usuarios/user_management.html')


@login_required
@administrador_required
def api_user_list(request):
    """Lists all users with their BU and role data."""
    membership = UserBUMembership.objects.filter(user=request.user).first()
    user_bu = membership.business_unit if membership else None

    # Superuser sees all; admin sees only their own BU
    if request.user.is_superuser:
        users = User.objects.all().order_by('username')
    else:
        users = User.objects.filter(
            userbumembership__business_unit=user_bu
        ).order_by('username')

    result = []
    for u in users:
        m = UserBUMembership.objects.filter(user=u).first()
        result.append({
            'id': u.id,
            'username': u.username,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'email': u.email,
            'is_active': u.is_active,
            'is_superuser': u.is_superuser,
            'date_joined': u.date_joined.strftime('%d/%m/%Y'),
            'last_login': u.last_login.strftime('%d/%m/%Y %H:%M') if u.last_login else '—',
            'bu': m.business_unit.name if m else '—',
            'bu_id': m.business_unit.id if m else None,
            'role': m.role if m else '—',
        })

    return JsonResponse({'users': result})


@login_required
@administrador_required
@require_http_methods(['POST'])
def api_user_edit(request, user_id):
    """Edits the BU, role and basic data of a user."""
    try:
        data = json.loads(request.body)

        target = User.objects.get(id=user_id)

        # Cannot edit a superuser unless the requester is also a superuser
        if target.is_superuser and not request.user.is_superuser:
            return JsonResponse({'error': 'Not allowed to edit a superuser'}, status=403)

        # Cannot edit yourself
        if target == request.user:
            return JsonResponse({'error': 'Cannot edit your own account here'}, status=400)

        # Update basic fields
        if 'first_name' in data:
            target.first_name = data['first_name'].strip()
        if 'last_name' in data:
            target.last_name = data['last_name'].strip()
        if 'email' in data:
            target.email = data['email'].strip()
        target.save()

        # Update BU and role
        bu_id = data.get('bu_id')
        role = data.get('role')

        if bu_id and role:
            bu = BusinessUnit.objects.get(id=bu_id)
            UserBUMembership.objects.update_or_create(
                user=target,
                defaults={'business_unit': bu, 'role': role}
            )

            # Update the Django group accordingly
            group_name = ROLE_TO_GROUP.get(role)
            if group_name:
                try:
                    group = Group.objects.get(name=group_name)
                    target.groups.clear()
                    target.groups.add(group)
                except Group.DoesNotExist:
                    pass

        log_audit(request.user, 'USER_EDIT',
                  target_user=target.username,
                  bu_id=bu_id,
                  role=role)

        return JsonResponse({'status': 'updated', 'username': target.username})

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except BusinessUnit.DoesNotExist:
        return JsonResponse({'error': 'BU not found'}, status=404)
    except Exception as e:
        logger.error(f'[api_user_edit] Error: {e}')
        log_error('api_user_edit', str(e))
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@administrador_required
@require_http_methods(['POST'])
def api_user_deactivate(request, user_id):
    """Deactivates a user (is_active=False). Never deletes."""
    try:
        target = User.objects.get(id=user_id)

        if target.is_superuser:
            return JsonResponse({'error': 'Cannot deactivate a superuser'}, status=400)

        if target == request.user:
            return JsonResponse({'error': 'Cannot deactivate your own account'}, status=400)

        target.is_active = False
        target.save()

        log_audit(request.user, 'USER_DEACTIVATE',
                  target_user=target.username,
                  ip=request.META.get('REMOTE_ADDR'))

        logger.info(f'[user_management] User deactivated: {target.username} by {request.user.username}')
        return JsonResponse({'status': 'deactivated', 'username': target.username})

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        logger.error(f'[api_user_deactivate] Error: {e}')
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@administrador_required
@require_http_methods(['POST'])
def api_user_activate(request, user_id):
    """Reactivates a deactivated user."""
    try:
        target = User.objects.get(id=user_id)
        target.is_active = True
        target.save()

        log_audit(request.user, 'USER_ACTIVATE',
                  target_user=target.username,
                  ip=request.META.get('REMOTE_ADDR'))

        return JsonResponse({'status': 'activated', 'username': target.username})

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@administrador_required
def api_bu_list(request):
    """Returns available BUs for the edit select input."""
    bus = BusinessUnit.objects.all().order_by('name')
    return JsonResponse({
        'bus': [{'id': bu.id, 'name': bu.name} for bu in bus]
    })

@login_required
@administrador_required
@require_http_methods(['POST'])
def api_user_create(request):
    """Creates a new user inline — admin only."""
    try:
        data = json.loads(request.body)
        username   = data.get('username', '').strip()
        password   = data.get('password', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name  = data.get('last_name', '').strip()
        email      = data.get('email', '').strip()
        bu_id      = data.get('bu_id')
        role       = data.get('role', 'viewer')

        if not username or not password:
            return JsonResponse({'error': 'Usuário e senha são obrigatórios'}, status=400)

        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': f'Usuário "{username}" já existe'}, status=400)

        if len(password) < 8:
            return JsonResponse({'error': 'Senha deve ter pelo menos 8 caracteres'}, status=400)

        bu = BusinessUnit.objects.filter(id=bu_id).first() if bu_id else None

        user = User.objects.create_user(
            username=username,
            password=password,
            first_name=first_name,
            last_name=last_name,
            email=email,
        )

        # Signal cria membership com a BU padrão — update_or_create corrige para a BU escolhida
        if bu:
            from apps.organizations.models import UserBUMembership
            UserBUMembership.objects.update_or_create(
                user=user,
                defaults={'business_unit': bu, 'role': role}
            )

        # Atribui grupo Django
        group_name = ROLE_TO_GROUP.get(role)
        if group_name:
            try:
                group = Group.objects.get(name=group_name)
                user.groups.clear()
                user.groups.add(group)
            except Group.DoesNotExist:
                pass

        log_audit(request.user, 'USER_CREATE',
                  target_user=username,
                  bu_id=bu_id,
                  role=role)

        return JsonResponse({
            'status': 'created',
            'id': user.id,
            'username': user.username,
        }, status=201)

    except Exception as e:
        logger.error(f'[api_user_create] Error: {e}')
        log_error('api_user_create', str(e))
        return JsonResponse({'error': str(e)}, status=500)