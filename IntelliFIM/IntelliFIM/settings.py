"""
Django settings with environment configuration
"""
import os
from pathlib import Path
from dotenv import load_dotenv
import dj_database_url
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
ENV_FILE = os.getenv('ENV_FILE', '.env.dev')
env_path = BASE_DIR / ENV_FILE

if env_path.exists():
    load_dotenv(env_path)
else:
    # Load default .env
    load_dotenv(BASE_DIR / '.env.dev')

# ==================== CORE SETTINGS ====================
SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
if ENVIRONMENT == 'production':
    ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')

# Application definition
INSTALLED_APPS = [
    # Django apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'drf_yasg',
    'django_filters',
    'django_celery_results',
    'django_celery_beat',
    
    # Your apps
    'accounts',
    'auditlogs',
    'channels',
    'fim',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # For static files
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'auditlogs.middleware.AuditMiddleware',  # If you have audit middleware
]

ROOT_URLCONF = 'IntelliFIM.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'IntelliFIM.wsgi.application'
ASGI_APPLICATION = 'IntelliFIM.asgi.application'


CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("127.0.0.1", 6379)],
        },
    },
}


CHANNEL_LAYERS["default"]["CONFIG"]["expiry"] = 3600

# ==================== DATABASE CONFIGURATION ====================
# Database pooling configuration
DB_POOL_OPTIONS = {
    'pool_size': int(os.getenv('DB_POOL_SIZE', 10)),
    'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', 20)),
    'pool_recycle': int(os.getenv('DB_POOL_RECYCLE', 3600)),
    'pool_timeout': int(os.getenv('DB_POOL_TIMEOUT', 30)),
}

# Main database (default)
DATABASES = {
    'default': {
        'ENGINE': os.getenv('DB_ENGINE', 'django.db.backends.postgresql'),
        'NAME': os.getenv('DB_NAME', 'fim_db'),
        'USER': os.getenv('DB_USER', 'fim_user'),
        'PASSWORD': os.getenv('DB_PASSWORD', ''),
        'HOST': os.getenv('DB_HOST', 'localhost'),
        'PORT': os.getenv('DB_PORT', '5432'),
        'CONN_MAX_AGE': int(os.getenv('DB_CONN_MAX_AGE', 300)),
        'OPTIONS': {
            'connect_timeout': 10,
        },
    },
    'auth_db': {
        'ENGINE': os.getenv('AUTH_DB_ENGINE', 'django.db.backends.postgresql'),
        'NAME': os.getenv('AUTH_DB_NAME', 'auth_db'),
        'USER': os.getenv('AUTH_DB_USER', 'fim_user'),
        'PASSWORD': os.getenv('AUTH_DB_PASSWORD', ''),
        'HOST': os.getenv('AUTH_DB_HOST', 'localhost'),
        'PORT': os.getenv('AUTH_DB_PORT', '5432'),
        'CONN_MAX_AGE': int(os.getenv('DB_CONN_MAX_AGE', 300)),
        'OPTIONS': {
            'connect_timeout': 10,
        },
    },
}

# Database routers
DATABASE_ROUTERS = ['IntelliFIM.db_routers.AuthFIMRouter']

# ==================== CACHE CONFIGURATION ====================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/2'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# ==================== CELERY CONFIGURATION ====================
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_ENABLE_UTC = True

# Task settings
CELERY_TASK_DEFAULT_QUEUE = 'default'
CELERY_TASK_TIME_LIMIT = 3600  # 1 hour
CELERY_TASK_SOFT_TIME_LIMIT = 3000  # 50 minutes
CELERY_TASK_MAX_RETRIES = 3
CELERY_TASK_DEFAULT_RETRY_DELAY = 30

# Queue configuration
CELERY_TASK_QUEUES = {
    'default': {
        'exchange': 'default',
        'routing_key': 'default',
    },
    'fim_monitor': {
        'exchange': 'fim_monitor',
        'routing_key': 'fim_monitor',
    },
    'fim_scans': {
        'exchange': 'fim_scans',
        'routing_key': 'fim_scans',
    },
    'fim_backup': {
        'exchange': 'fim_backup',
        'routing_key': 'fim_backup',
    },
}

# ==================== REST FRAMEWORK ====================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',  # Only in dev
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day',
    }
}

# Hide browsable API in production
if ENVIRONMENT == 'production':
    REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES'] = [
        'rest_framework.renderers.JSONRenderer',
    ]

# ==================== SECURITY SETTINGS ====================
# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Security headers
if ENVIRONMENT == 'production':
    # HTTPS settings
    SECURE_SSL_REDIRECT = os.getenv('SECURE_SSL_REDIRECT', 'True').lower() == 'true'
    SECURE_HSTS_SECONDS = int(os.getenv('SECURE_HSTS_SECONDS', 31536000))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    
    # Cookie settings
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    
    # Content Security Policy (CSP) - basic setup
    CSP_DEFAULT_SRC = ("'self'",)
    CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
    CSP_SCRIPT_SRC = ("'self'",)
else:
    SECURE_SSL_REDIRECT = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False

# CORS settings
CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]
CORS_ALLOW_HEADERS = [
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

# ==================== FILE SETTINGS ====================
# Static files (CSS, JavaScript, Images)
# STATIC_URL = '/static/'
# STATIC_ROOT = BASE_DIR / 'staticfiles'
# STATICFILES_DIRS = [BASE_DIR / 'static']

# Media files
# MEDIA_URL = '/media/'
# MEDIA_ROOT = BASE_DIR / 'media'

# Static files serving in production
# STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# File upload settings
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880   # 5MB

# ==================== FIM SPECIFIC SETTINGS ====================
FIM_SETTINGS = {
    'LOG_DIR': Path(os.getenv('FIM_LOG_DIR', BASE_DIR / 'logs')),
    'BACKUP_DIR': Path(os.getenv('FIM_BACKUP_DIR', BASE_DIR / 'backups')),
    'REPORT_DIR': Path(os.getenv('FIM_REPORT_DIR', BASE_DIR / 'reports')),
    'MAX_FILE_SIZE': int(os.getenv('FIM_MAX_FILE_SIZE', 104857600)),  # 100MB
    'SCAN_INTERVAL': int(os.getenv('FIM_SCAN_INTERVAL', 300)),  # 5 minutes
    'HASH_ALGORITHM': os.getenv('FIM_HASH_ALGORITHM', 'sha256'),
    'ARCHIVE_DAYS': int(os.getenv('FIM_ARCHIVE_DAYS', 30)),
    'WORKER_COUNT': int(os.getenv('FIM_WORKER_COUNT', 4)),
}

# Create directories if they don't exist
for key in ['LOG_DIR', 'BACKUP_DIR', 'REPORT_DIR']:
    dir_path = FIM_SETTINGS[key]
    dir_path.mkdir(parents=True, exist_ok=True)

# ==================== LOGGING CONFIGURATION ====================
LOG_LEVEL = os.getenv('LOGGING_LEVEL', 'INFO').upper()

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'fim_format': {
            'format': '{asctime} - {name} - {levelname} - {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': FIM_SETTINGS['LOG_DIR'] / 'django.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'fim_file': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': FIM_SETTINGS['LOG_DIR'] / 'fim.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'fim_format',
        },
        'celery_file': {
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': FIM_SETTINGS['LOG_DIR'] / 'celery.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': True,
        },
        'django.db.backends': {
            'handlers': ['console'] if os.getenv('DEBUG_SQL', 'False').lower() == 'true' else [],
            'level': 'DEBUG' if os.getenv('DEBUG_SQL', 'False').lower() == 'true' else 'WARNING',
            'propagate': False,
        },
        'fim': {
            'handlers': ['console', 'fim_file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'celery': {
            'handlers': ['console', 'celery_file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
    },
}

# ==================== SENTRY CONFIGURATION ====================
SENTRY_DSN = os.getenv('SENTRY_DSN', '')
if SENTRY_DSN and ENVIRONMENT == 'production':
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[DjangoIntegration()],
        traces_sample_rate=1.0,
        send_default_pii=True,
        environment=ENVIRONMENT,
    )

# ==================== EMAIL CONFIGURATION ====================
EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.getenv('EMAIL_HOST', 'localhost')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() == 'true'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', '')

# ==================== INTERNATIONALIZATION ====================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ==================== DEFAULT AUTO FIELD ====================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ==================== SWAGGER SETTINGS ====================
SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    },
    'USE_SESSION_AUTH': False,
    'JSON_EDITOR': True,
    'DOC_EXPANSION': 'none',
    'APIS_SORTER': 'alpha',
    'SHOW_REQUEST_HEADERS': True,
}

# Hide Swagger in production
if ENVIRONMENT == 'production':
    SWAGGER_SETTINGS['DEFAULT_API_URL'] = None
