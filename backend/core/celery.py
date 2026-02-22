import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings.production')

app = Celery('land_contract')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Configure Celery beat schedule
app.conf.beat_schedule = {
    # Send daily contract expiry notifications
    'send-contract-expiry-notifications': {
        'task': 'apps.notifications.tasks.send_contract_expiry_notifications',
        'schedule': 60.0 * 60.0 * 24.0,  # Run daily
    },
    
    # Clean up expired sessions
    'cleanup-expired-sessions': {
        'task': 'apps.users.tasks.cleanup_expired_sessions',
        'schedule': 60.0 * 60.0,  # Run hourly
    },
    
    # Sync with Rosreestr
    'sync-rosreestr-data': {
        'task': 'apps.integrations.tasks.sync_rosreestr_data',
        'schedule': 60.0 * 60.0 * 6.0,  # Run every 6 hours
    },
    
    # Generate daily reports
    'generate-daily-reports': {
        'task': 'apps.contracts.tasks.generate_daily_reports',
        'schedule': 60.0 * 60.0 * 24.0,  # Run daily at midnight
    },
    
    # Backup database
    'backup-database': {
        'task': 'apps.core.tasks.backup_database',
        'schedule': 60.0 * 60.0 * 24.0,  # Run daily
    },
}

# Configure task routing
app.conf.task_routes = {
    'apps.users.tasks.*': {'queue': 'users'},
    'apps.contracts.tasks.*': {'queue': 'contracts'},
    'apps.land_plots.tasks.*': {'queue': 'land_plots'},
    'apps.integrations.tasks.*': {'queue': 'integrations'},
    'apps.notifications.tasks.*': {'queue': 'notifications'},
    'apps.core.tasks.*': {'queue': 'core'},
}

# Configure task priorities
app.conf.task_default_priority = 5
app.conf.worker_prefetch_multiplier = 1

# Configure task execution time limits
app.conf.task_soft_time_limit = 300  # 5 minutes
app.conf.task_time_limit = 600  # 10 minutes

# Configure task result backend
app.conf.result_backend = settings.CELERY_RESULT_BACKEND

# Configure broker connection
app.conf.broker_url = settings.CELERY_BROKER_URL

# Configure worker settings
app.conf.worker_max_tasks_per_child = 1000
app.conf.worker_disable_rate_limits = False

# Configure task serialization
app.conf.task_serializer = 'json'
app.conf.result_serializer = 'json'
app.conf.accept_content = ['json']

# Configure timezone
app.conf.timezone = settings.TIME_ZONE
app.conf.enable_utc = True

# Configure task tracking
app.conf.task_track_started = True
app.conf.task_send_sent_event = True

# Configure error handling
app.conf.task_reject_on_worker_lost = True
app.conf.task_acks_late = True

# Configure monitoring
app.conf.worker_send_task_events = True
app.conf.task_send_sent_event = True

@app.task(bind=True)
def debug_task(self):
    """Debug task to test Celery configuration."""
    print(f'Request: {self.request!r}')