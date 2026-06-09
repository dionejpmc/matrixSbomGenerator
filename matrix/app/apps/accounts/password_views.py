"""
apps/accounts/password_views.py
"""
import logging
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render

logger = logging.getLogger(__name__)


@login_required
def force_password_change_view(request):
    if request.method == 'GET':
        return render(request, 'accounts/force_password_change.html')

    new_password = request.POST.get('new_password', '').strip()
    confirm_password = request.POST.get('confirm_password', '').strip()

    if not new_password:
        return render(request, 'accounts/force_password_change.html',
                     {'error': 'Nova senha é obrigatória.'})
    if len(new_password) < 8:
        return render(request, 'accounts/force_password_change.html',
                     {'error': 'A senha deve ter pelo menos 8 caracteres.'})
    if new_password != confirm_password:
        return render(request, 'accounts/force_password_change.html',
                     {'error': 'As senhas não coincidem.'})
    if new_password == 'admin':
        return render(request, 'accounts/force_password_change.html',
                     {'error': 'Escolha uma senha mais segura.'})

    request.user.set_password(new_password)
    request.user.save()

    # Remove a flag
    try:
        request.user.profile.must_change_password = False
        request.user.profile.save(update_fields=['must_change_password'])
    except Exception:
        pass

    update_session_auth_hash(request, request.user)
    logger.info(f'[force_password_change] Senha alterada: {request.user.username}')

    return render(request, 'accounts/force_password_change.html', {'success': True})