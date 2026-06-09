from django.apps import AppConfig

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.accounts'  # Must match the exact folder path

    def ready(self):
        # Load RBAC signals to auto-create the user profile on account creation
        import apps.accounts.signals