"""
Django settings for AVAGuard Web Portal.

Hardened for team collaboration:
- All config read from .env with safe fallbacks
- OTP_ENABLED flag to skip 2FA during development
- Auto-creates logs/ directory
- Console email fallback when credentials missing
"""

import os
import sys
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env FIRST — before anything else reads env vars
load_dotenv(BASE_DIR / '.env')

# --- AVAGuard Core Integration ---
# (Web Portal directly imports avaguard_core using the installed package)
PROJECT_ROOT = BASE_DIR.parent

# ==============================================================================
# Core Settings (from .env with safe fallbacks)
# ==============================================================================
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-insecure-key-change-in-production')
DEBUG = os.getenv('DEBUG', 'True') == 'True'
ALLOWED_HOSTS = [h.strip() for h in os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',') if h.strip()]

# OTP / 2FA toggle — set OTP_ENABLED=True in .env to enforce 2FA
OTP_ENABLED = os.getenv('OTP_ENABLED', 'False') == 'True'

# ── FAIL-FAST SAFETY ──
# Block production deployment with default insecure key
if not DEBUG and SECRET_KEY == 'dev-insecure-key-change-in-production':
    raise RuntimeError(
        'FATAL: SECRET_KEY is set to the default insecure value. '
        'Set a strong SECRET_KEY in .env before running with DEBUG=False.'
    )

# Secure cookie settings for production
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True

# ==============================================================================
# Application definition
# ==============================================================================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third-party
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    # Local apps
    'core',
    'api',
]

# Conditionally add OTP apps only when enabled
if OTP_ENABLED:
    INSTALLED_APPS += [
        'django_otp',
        'django_otp.plugins.otp_totp',
        'two_factor',
    ]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]

# Conditionally add OTP middleware
if OTP_ENABLED:
    MIDDLEWARE.append('django_otp.middleware.OTPMiddleware')

MIDDLEWARE += [
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # AVAGuard Security Middleware
    'core.middleware.RateLimitMiddleware',
    'core.middleware.SecurityHeadersMiddleware',
    'core.middleware.FirstLoginMiddleware',
]

ROOT_URLCONF = 'config.urls'

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

WSGI_APPLICATION = 'config.wsgi.application'

# ==============================================================================
# Database — Auto-switches based on environment
#   Local/Desktop: SQLite (default, zero config)
#   Team/Production: PostgreSQL via Supabase (set DB_ENGINE in .env)
# ==============================================================================
_db_engine = os.getenv('DB_ENGINE', 'sqlite3')

if _db_engine == 'postgresql':
    # PostgreSQL — Supabase or any hosted PostgreSQL
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME', 'postgres'),
            'USER': os.getenv('DB_USER', 'postgres'),
            'PASSWORD': os.getenv('DB_PASSWORD', ''),
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '5432'),
            'CONN_MAX_AGE': int(os.getenv('DB_CONN_MAX_AGE', '60')),
            'CONN_HEALTH_CHECKS': True,
            'OPTIONS': {
                'sslmode': os.getenv('DB_SSLMODE', 'require'),
            },
        }
    }
else:
    # SQLite — local development and Desktop app
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# ==============================================================================
# Password validation
# ==============================================================================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Custom User Model
AUTH_USER_MODEL = 'core.User'

# ==============================================================================
# Authentication Redirects
# ==============================================================================
LOGIN_URL = '/auth/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/auth/login/'

# ==============================================================================
# Internationalization
# ==============================================================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# ==============================================================================
# Static files
# ==============================================================================
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
WHITENOISE_USE_FINDERS = True

# ==============================================================================
# Default primary key field type
# ==============================================================================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ==============================================================================
# Django REST Framework
# ==============================================================================
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
}

# ==============================================================================
# JWT Configuration
# ==============================================================================
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_OBTAIN_SERIALIZER': 'rest_framework_simplejwt.serializers.TokenObtainPairSerializer',
}

# ==============================================================================
# CORS Configuration (for Desktop App)
# ==============================================================================
import os
CORS_ALLOWED_ORIGINS = [
    os.getenv('PORTAL_CORS_ORIGIN', 'http://localhost:8000'),
    os.getenv('PORTAL_CORS_ORIGIN_ALT', 'http://127.0.0.1:8000'),
]
CORS_ALLOW_CREDENTIALS = True

if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True

# ==============================================================================
# Logging Configuration (auto-creates logs/ directory locally, logs to console on Vercel)
# ==============================================================================
IS_VERCEL = 'VERCEL' in os.environ

if IS_VERCEL:
    # On Vercel, we only log to console (stdout/stderr) to respect the read-only filesystem
    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '{levelname} {asctime} {module} {message}',
                'style': '{',
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'django': {
                'handlers': ['console'],
                'level': 'INFO',
                'propagate': True,
            },
            'api': {
                'handlers': ['console'],
                'level': 'DEBUG',
                'propagate': True,
            },
        },
    }
else:
    # Local File Logging Configuration
    LOGS_DIR = BASE_DIR / 'logs'
    os.makedirs(LOGS_DIR, exist_ok=True)

    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '{levelname} {asctime} {module} {message}',
                'style': '{',
            },
        },
        'handlers': {
            'file': {
                'level': 'INFO',
                'class': 'logging.FileHandler',
                'filename': LOGS_DIR / 'django.log',
                'formatter': 'verbose',
            },
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'django': {
                'handlers': ['file', 'console'],
                'level': 'INFO',
                'propagate': True,
            },
            'api': {
                'handlers': ['file', 'console'],
                'level': 'DEBUG',
                'propagate': True,
            },
        },
    }

# ==============================================================================
# Email Configuration
# ==============================================================================
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = 'AVAGuard Security <noreply@avaguard.com>'

# Fallback to console if email not configured
if not EMAIL_HOST_USER or not EMAIL_HOST_PASSWORD:
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# ==============================================================================
# Cache Configuration (for Rate Limiting)
# ==============================================================================
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'avaguard-rate-limit-cache',
    }
}

# ==============================================================================
# Security Settings
# ==============================================================================
RATE_LIMIT_LOGIN_ATTEMPTS = 5
RATE_LIMIT_LOCKOUT_MINUTES = 15
RATE_LIMIT_OTP_ATTEMPTS = 10
RATE_LIMIT_OTP_LOCKOUT_MINUTES = 30

# Default Organization
DEFAULT_ORGANIZATION_NAME = 'AVAGuard'

# Sudo-mode validity window (seconds)
SUDO_VALIDITY_SECONDS = 300  # 5 minutes

# ==============================================================================
# Production Deployment Settings
# ==============================================================================
# The following settings are flagged by `python manage.py check --deploy`.
# They are deliberately disabled in local development to prevent breaking the local dev server.
# In production, ensure these are configured via environment variables or a production settings file:
# - SECURE_HSTS_SECONDS: Must be set to a positive integer (e.g., 31536000) when served over HTTPS.
# - SECURE_SSL_REDIRECT: Must be True to force HTTPS.
# - SESSION_COOKIE_SECURE: Must be True for secure session cookies.
# - CSRF_COOKIE_SECURE: Must be True for secure CSRF cookies.
# - SECRET_KEY: Must be a long, random, securely generated value.
# - DEBUG: Must be False.
