from django.conf import settings

def app_branding(request):
    return {
        'APP_NAME': getattr(settings, 'APP_NAME', 'Matrix'),
    }