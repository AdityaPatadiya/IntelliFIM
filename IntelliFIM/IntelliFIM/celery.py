"""
project/celery.py
-----------------
Celery configuration for Django FIM project
"""
import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project.settings')

app = Celery('fim_project')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps
app.autodiscover_tasks()

# Optional: Periodic tasks for scheduled FIM scans
app.conf.beat_schedule = {
    # Keep cleanup task
    'cleanup-old-logs': {
        'task': 'fim.tasks.cleanup_old_data',
        'schedule': crontab(hour=3, minute=0),
    },
    # Keep health check
    'check-monitoring-health': {
        'task': 'fim.tasks.check_monitoring_health',
        'schedule': crontab(minute='*/5'),
    },
}

# Task routing
app.conf.task_routes = {
    'fim.tasks.start_fim_monitoring_task': {'queue': 'fim_monitor'},
    'fim.tasks.stop_fim_monitoring_task': {'queue': 'fim_monitor'},
    'fim.tasks.perform_manual_scan': {'queue': 'fim_scans'},
    'fim.tasks.perform_scheduled_scan': {'queue': 'fim_scans'},
    'fim.tasks.restore_file_task': {'queue': 'fim_backup'},
    'fim.tasks.create_backup_task': {'queue': 'fim_backup'},
    'fim.tasks.*': {'queue': 'default'},
}

# Task timeouts (in seconds)
app.conf.task_time_limit = 3600  # 1 hour max
app.conf.task_soft_time_limit = 3000  # 50 minutes warning

# Task retry settings
app.conf.task_default_retry_delay = 30  # 30 seconds
app.conf.task_max_retries = 3

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')


@app.task(bind=True)
def test_celery_task(self, message):
    """Test task to verify Celery is working"""
    print(f"Celery test: {message}")
    return f"Task completed: {message}"
