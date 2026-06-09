from django.apps import AppConfig

class SbomConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.sbom'  # Full module path
    label = 'sbom'      # Alias Django uses for migrations