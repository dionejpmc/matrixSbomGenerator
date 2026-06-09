"""
apps/accounts/middleware.py
Redirects users to the password change page if must_change_password is True.
"""
from django.shortcuts import redirect

EXEMPT_URLS = [
    '/accounts/change-password/',
    '/accounts/login/',
    '/logoff/',
    '/static/',
    '/media/',
    '/oidc/',
]


class ForcePasswordChangeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            exempt = any(request.path.startswith(url) for url in EXEMPT_URLS)
            if not exempt:
                try:
                    if request.user.profile.must_change_password:
                        return redirect('force_password_change')
                except Exception:
                    pass

        return self.get_response(request)