import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'alx_backend_security.settings')

app = Celery('alx_backend_security')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Celery Beat Schedule for periodic tasks
from celery.schedules import crontab

app.conf.beat_schedule = {
    'detect-anomalies-hourly': {
        'task': 'ip_tracking.tasks.detect_anomalies',
        'schedule': crontab(minute=0),  # Every hour at minute 0
    },
    'cleanup-old-suspicious-records': {
        'task': 'ip_tracking.tasks.cleanup_old_suspicious_records',
        'schedule': crontab(hour=2, minute=0),  # Daily at 2:00 AM
    },
    'generate-security-report': {
        'task': 'ip_tracking.tasks.generate_security_report',
        'schedule': crontab(hour=6, minute=0),  # Daily at 6:00 AM
    },
}

app.conf.timezone = 'UTC'
