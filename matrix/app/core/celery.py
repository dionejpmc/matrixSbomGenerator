import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('matrix')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.conf.include = [
    'tasks.sbom_tasks',
    'tasks.scan_tasks',
    'tasks.rauc_tasks',
    'tasks.ext4_tasks',
    'tasks.scheduled_tasks',
]

app.conf.beat_schedule = {
    # Update Grype database at 02:00
    'update-grype-db': {
        'task': 'tasks.scheduled_tasks.update_grype_db',
        'schedule': crontab(hour=2, minute=0),
    },
    # Re-scan all SBOMs at 03:00
    'daily-rescan-all': {
        'task': 'tasks.scheduled_tasks.daily_rescan_all',
        'schedule': crontab(hour=3, minute=0),
    },
    # PG↔Neo4j integrity check at 05:00
    'daily-integrity-check': {
        'task': 'tasks.scheduled_tasks.daily_integrity_check',
        'schedule': crontab(hour=5, minute=0),
    },
}

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')