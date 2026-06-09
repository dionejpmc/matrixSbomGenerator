"""
core/permissions.py

Group-based permission decorators and helpers.

Groups:
  - Administrador → full access
  - Operador      → read + write, no deletion of SBOMs/products
  - Visualizador  → read-only, no access to Hunting

Usage in views:
    from core.permissions import require_group, administrador_required, operador_required

    @require_group('Administrador', 'Operador')
    def my_view(request): ...

    @administrador_required
    def delete_product(request, id): ...
"""
from functools import wraps
from django.http import JsonResponse
from django.shortcuts import redirect
from django.contrib import messages


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def get_user_group(user):
    """Returns the primary group name for the user."""
    if user.is_superuser:
        return 'Administrador'
    return user.groups.values_list('name', flat=True).first()


def is_administrador(user):
    return user.is_superuser or user.groups.filter(name='Administrador').exists()


def is_operador(user):
    return is_administrador(user) or user.groups.filter(name='Operador').exists()


def is_visualizador(user):
    """Viewer is any authenticated user with a defined group."""
    return user.is_authenticated


# ─────────────────────────────────────────────────────────────
# DECORATOR GENÉRICO
# ─────────────────────────────────────────────────────────────

def require_group(*groups):
    """
    Decorator that requires the user to belong to at least one of the given groups.
    For API requests (/api/ URLs) or AJAX/fetch calls, returns a 403 JSON response.
    For regular pages, redirects to the dashboard with an error message.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')

            user_groups = set(request.user.groups.values_list('name', flat=True))
            allowed = set(groups)

            # Superuser sempre passa
            if request.user.is_superuser or user_groups & allowed:
                return view_func(request, *args, **kwargs)

            # Detect API or AJAX/fetch request
            is_api = (
                '/api/' in request.path
                or request.method == 'POST'
                or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                or 'application/json' in request.headers.get('Accept', '')
                or 'application/json' in request.headers.get('Content-Type', '')
            )

            if is_api:
                return JsonResponse(
                    {'error': 'Operação não permitida por falta de privilégios.'},
                    status=403
                )

            # HTML page → redirect with error message
            messages.error(
                request,
                'Operação não permitida por falta de privilégios.'
            )
            return redirect('dashboard')

        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────
# SHORTCUTS
# ─────────────────────────────────────────────────────────────

def administrador_required(view_func):
    """Administrator (or superuser) only."""
    return require_group('Administrador')(view_func)


def operador_required(view_func):
    """Operator or Administrator (or superuser)."""
    return require_group('Operador', 'Administrador')(view_func)


def hunting_required(view_func):
    """Operator or Administrator — Viewer cannot access Hunting."""
    return require_group('Operador', 'Administrador')(view_func)