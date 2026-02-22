"""
Production settings for land contracts system
"""
import os
from pathlib import Path
from decouple import config, Csv
from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default=Csv(), cast=Csv)

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
        'OPTIONS': {
            'sslmode': 'require',
            'sslcert': config('DB_SSL_CERT', default=''),
            'sslkey': config('DB_SSL_KEY', default=''),
            'sslrootcert': config('DB_SSL_ROOT_CERT', default=''),
        },
        'CONN_MAX_AGE': 60,
    }
}

# Cache
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True,
            },
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'RETRY_ON_TIMEOUT': True,
            'TIMEOUT': 5,
        },
        'KEY_PREFIX': 'land_contracts',
        'TIMEOUT': 300,
    }
}

# Session
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 86400  # 24 hours

# Security
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = 'HTTP_X_FORWARDED_PROTO'
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# CORS
CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', default=Csv(), cast=Csv)
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]
CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# Email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL')
SERVER_EMAIL = config('SERVER_EMAIL', default=DEFAULT_FROM_EMAIL)

# Storage
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY')
AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME')
AWS_S3_REGION_NAME = config('AWS_S3_REGION_NAME', default='eu-central-1')
AWS_S3_CUSTOM_DOMAIN = config('AWS_S3_CUSTOM_DOMAIN', default='')
AWS_DEFAULT_ACL = 'private'
AWS_S3_FILE_OVERWRITE = False
AWS_S3_MAX_MEMORY_SIZE = 100 * 1024 * 1024  # 100MB

# Celery Configuration
CELERY_BROKER_URL = config('CELERY_BROKER_URL')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Europe/Moscow'
CELERY_BEAT_SCHEDULE = {
    'cleanup-expired-tokens': {
        'task': 'apps.authentication.tasks.cleanup_expired_tokens',
        'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours
    },
    'process-notifications': {
        'task': 'apps.notifications.tasks.process_pending_notifications',
        'schedule': crontab(minute='*/5'),  # Every 5 minutes
    },
    'backup-database': {
        'task': 'apps.core.tasks.backup_database',
        'schedule': crontab(minute=0, hour=2),  # Daily at 2 AM
    },
    'sync-with-rosreestr': {
        'task': 'apps.integration.tasks.sync_land_plots_data',
        'schedule': crontab(minute=0, hour='*/12'),  # Every 12 hours
    },
}

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'json': {
            'format': '{"level": "{levelname}", "time": "{asctime}", "module": "{module}", "process": {process:d}, "thread": {thread:d}, "message": "{message}"}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/land-contracts/django.log',
            'maxBytes': 1024 * 1024 * 100,  # 100MB
            'backupCount': 5,
            'formatter': 'json',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'sentry': {
            'level': 'ERROR',
            'class': 'sentry_sdk.integrations.django.SentryHandler',
        },
    },
    'root': {
        'handlers': ['file', 'sentry'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'sentry'],
            'level': 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['file', 'sentry'],
            'level': 'INFO',
            'propagate': False,
        },
        'celery': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Sentry
SENTRY_DSN = config('SENTRY_DSN', default='')
SENTRY_ENVIRONMENT = 'production'
SENTRY_RELEASE = config('APP_VERSION', default='1.0.0')
SENTRY_TRACES_SAMPLE_RATE = config('SENTRY_TRACES_SAMPLE_RATE', default=0.1, cast=float)

# Application settings
SITE_URL = config('SITE_URL')
FRONTEND_URL = config('FRONTEND_URL')
API_VERSION = 'v1'

# Electronic Signature
CRYPTOPRO_URL = config('CRYPTOPRO_URL', default='https://api.cryptopro.ru')
CRYPTOPRO_CERT_PATH = config('CRYPTOPRO_CERT_PATH', default='/etc/cryptopro/certs')
CRYPTOPRO_KEY_PATH = config('CRYPTOPRO_KEY_PATH', default='/etc/cryptopro/keys')

# Rosreestr Integration
ROSREESTR_API_URL = config('ROSREESTR_API_URL', default='https://rosreestr.ru/api')
ROSREESTR_API_KEY = config('ROSREESTR_API_KEY')
ROSREESTR_TIMEOUT = config('ROSREESTR_TIMEOUT', default=30, cast=int)

# Payment Integration
PAYMENT_PROVIDERS = {
    'sberbank': {
        'API_URL': config('SBERBANK_API_URL'),
        'MERCHANT_ID': config('SBERBANK_MERCHANT_ID'),
        'SECRET_KEY': config('SBERBANK_SECRET_KEY'),
        'TIMEOUT': config('SBERBANK_TIMEOUT', default=30, cast=int),
    },
    'tinkoff': {
        'API_URL': config('TINKOFF_API_URL'),
        'TERMINAL_KEY': config('TINKOFF_TERMINAL_KEY'),
        'SECRET_KEY': config('TINKOFF_SECRET_KEY'),
        'TIMEOUT': config('TINKOFF_TIMEOUT', default=30, cast=int),
    },
}

# Monitoring
PROMETHEUS_MULTIPROC_DIR = '/tmp/prometheus_multiproc_dir'
PROMETHEUS_METRICS_ENABLED = True

# Rate Limiting
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'
RATELIMIT_BLOCK = config('RATELIMIT_BLOCK', default='1h')

# File Upload
FILE_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024  # 50MB
FILE_UPLOAD_ALLOWED_EXTENSIONS = [
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 
    'jpg', 'jpeg', 'png', 'tiff', 'bmp'
]
FILE_UPLOAD_MAX_SIZE = 100 * 1024 * 1024  # 100MB

# Data Retention
DATA_RETENTION_DAYS = {
    'personal_data': 3650,  # 10 years
    'contracts': 3650,     # 10 years
    'documents': 3650,     # 10 years
    'audit_logs': 2555,     # 7 years
    'access_logs': 90,      # 3 months
}

# Security Headers
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy': (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' https://api.cryptopro.ru https://rosreestr.ru; "
        "frame-ancestors 'none';"
    ),
}

# Performance
USE_TZ = True
TIME_ZONE = 'Europe/Moscow'
LANGUAGE_CODE = 'ru-ru'
USE_I18N = True
USE_L10N = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = '/var/www/land-contracts/static/'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = '/var/www/land-contracts/media/'

# Health checks
HEALTH_CHECKS = {
    'database': 'apps.core.health_checks.DatabaseCheck',
    'cache': 'apps.core.health_checks.CacheCheck',
    'storage': 'apps.core.health_checks.StorageCheck',
    'external_apis': 'apps.core.health_checks.ExternalAPICheck',
}

# Feature flags
FEATURE_FLAGS = {
    'ENABLE_ANALYTICS': config('ENABLE_ANALYTICS', default=True, cast=bool),
    'ENABLE_PREDICTIVE_PRICING': config('ENABLE_PREDICTIVE_PRICING', default=False, cast=bool),
    'ENABLE_MOBILE_APP': config('ENABLE_MOBILE_APP', default=False, cast=bool),
    'ENABLE_API_V2': config('ENABLE_API_V2', default=False, cast=bool),
}