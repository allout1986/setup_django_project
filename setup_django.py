#!/usr/bin/python3
import os
import re
import secrets
import subprocess
import sys


class VirtualEnvManager:
    @staticmethod
    def create_virtual_env():
        subprocess.run(["python3", "-m", "venv", "venv"])


class PackageManager:
    @staticmethod
    def install_packages():
        subprocess.run(
            [
                "./venv/bin/pip",
                "install",
                "django",
                "gunicorn",
                "psycopg2-binary",
                "celery",
                "django_celery_results",
                "django-celery-beat",
                "redis",
                "django-auth-ldap",
                "django-rest-framework",
                "django-filter",
                "drf-yasg",
                "djangorestframework-simplejwt",
                "djangorestframework-simplejwt[crypto]",
                "drf-api-logger",
            ]
        )

    @staticmethod
    def freeze_packages(project_name):
        subprocess.run(
            ["./venv/bin/pip", "freeze"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output = subprocess.run(
            ["./venv/bin/pip", "freeze"], capture_output=True, text=True
        ).stdout
        with open(f"{project_name}/requirements.txt", "w") as file:
            file.write(output)


class EnvFileGenerator:
    @staticmethod
    def generate_env_files(project_name):
        # Updated environment content with database configuration variables
        env_content = {
            "development": f"""# Base environment variables
WEB_HOST={project_name}_web
CELERY_HOST={project_name}_celery
BEAT_HOST={project_name}_beat
REDIS_HOST={project_name}_redis
FLOWER_HOST={project_name}_flower
DB_HOST={project_name}_db
ALLOWED_HOSTS=*
SECRET_KEY=your_secret_key_development
SIMPLE_JWT_SECRET_KEY=your_secret_key_development
DEBUG=True
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_PASSWORD=admin
DJANGO_SUPERUSER_EMAIL=admin@email.com
""",
            "production": f"""# Base environment variables
WEB_HOST={project_name}_web
CELERY_HOST={project_name}_celery
BEAT_HOST={project_name}_beat
REDIS_HOST={project_name}_redis
FLOWER_HOST={project_name}_flower
DB_HOST={project_name}_db
ALLOWED_HOSTS=*
SECRET_KEY=your_secret_key_production
SIMPLE_JWT_SECRET_KEY=your_secret_key_production
DEBUG=False
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_PASSWORD=admin
DJANGO_SUPERUSER_EMAIL=admin@email.com
""",
        }

        for env, content in env_content.items():
            with open(f"{project_name}/.env.{env}", "w") as env_file:
                env_file.write(content)

    @staticmethod
    def add_celery_env_variables(project_name):
        celery_env_variables = """
# CELERY Configuration
CELERY_BROKER_URL=redis://$REDIS_HOST:6379/0
CELERY_RESULT_BACKEND=redis://$REDIS_HOST:6379/0

# FLOWER Configuration
FLOWER_BASIC_AUTH=admin:admin
FLOWER_PERSISTENT=True
FLOWER_PORT=5555
FLOWER_URL_PREFIX=flower
"""
        env_files = [
            f"{project_name}/.env.development",
            f"{project_name}/.env.production",
        ]
        for env_file in env_files:
            with open(env_file, "a") as file:
                file.write(celery_env_variables)

    @staticmethod
    def add_postgres_env_variables(project_name):
        postgres_env_variables = """
# POSTGRES Docker Configuration
POSTGRES_DB=your_db_name
POSTGRES_USER=your_db_user
POSTGRES_PASSWORD=your_db_password

# POSTGRES Django Configuration
DB_NAME=$POSTGRES_DB
DB_USER=$POSTGRES_USER
DB_PASSWORD=$POSTGRES_PASSWORD
DB_PORT=5432
"""
        env_files = [
            f"{project_name}/.env.development",
            f"{project_name}/.env.production",
        ]
        for env_file in env_files:
            with open(env_file, "a") as file:
                file.write(postgres_env_variables)

    @staticmethod
    def add_ldap_env_variables(project_name):
        ldap_env_variables = """
# LDAP Configuration
LDAP_SERVER_URI=ldap://your_ldap_server
LDAP_BIND_DN=cn=read-only-admin,dc=example,dc=com
LDAP_BIND_PASSWORD=your_bind_password
LDAP_USER_SEARCH_BASE_DN=ou=users,dc=example,dc=com
LDAP_GROUP_SEARCH_BASE_DN=ou=groups,dc=example,dc=com
"""
        env_files = [
            f"{project_name}/.env.development",
            f"{project_name}/.env.production",
        ]
        for env_file in env_files:
            with open(env_file, "a") as file:
                file.write(ldap_env_variables)


class DjangoProjectCreator:
    @staticmethod
    def create_project(project_name):
        subprocess.run(["./venv/bin/django-admin", "startproject", project_name])


class SettingsConfigurer:
    @staticmethod
    def configure_basic_settings(project_name):
        settings_path = f"{project_name}/{project_name}/settings.py"
        with open(settings_path, "r") as file:
            original_content = file.read()

        # Ensure 'import os' is present
        if "import os" not in original_content:
            original_content = "import os\n" + original_content

        # Use regular expression to replace SECRET_KEY
        new_content = re.sub(
            r"SECRET_KEY = .+", "SECRET_KEY = os.getenv('SECRET_KEY')", original_content
        )
        new_content = new_content.replace(
            "DEBUG = True", "DEBUG = os.getenv('DEBUG') == 'True'"
        )
        new_content = new_content.replace(
            "ALLOWED_HOSTS = []",
            "ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')",
        )

        with open(settings_path, "w") as file:
            file.write(new_content)

    @staticmethod
    def configure_database_settings(project_name):
        settings_path = f"{project_name}/{project_name}/settings.py"
        with open(settings_path, "r") as file:
            original_content = file.read()

        db_config = """DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT', '5432'),
    }
}
"""
        original_databases_block = """DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}"""
        new_content = original_content.replace(original_databases_block, db_config)

        with open(settings_path, "w") as file:
            file.write(new_content)

    @staticmethod
    def add_static_root(project_name):
        settings_path = f"{project_name}/{project_name}/settings.py"
        with open(settings_path, "r") as file:
            lines = file.readlines()

        # Check if STATIC_ROOT already exists
        if any("STATIC_ROOT" in line for line in lines):
            return

        # Find the line with STATIC_URL
        for i, line in enumerate(lines):
            if line.strip().startswith("STATIC_URL"):
                # Insert the STATIC_ROOT configuration after this line
                lines.insert(i + 1, f'STATIC_ROOT = os.path.join(BASE_DIR, "static")\n')
                break

        # Write the file back out
        with open(settings_path, "w") as file:
            file.writelines(lines)

    @staticmethod
    def add_ldap_configuration(project_name):
        settings_path = f"{project_name}/{project_name}/settings.py"
        ldap_settings = """
# LDAP Authentication
import ldap
from django_auth_ldap.config import LDAPSearch, PosixGroupType

AUTHENTICATION_BACKENDS = ['django_auth_ldap.backend.LDAPBackend', 'django.contrib.auth.backends.ModelBackend',]

AUTH_LDAP_SERVER_URI = os.getenv('LDAP_SERVER_URI')

AUTH_LDAP_BIND_DN = os.getenv('LDAP_BIND_DN')
AUTH_LDAP_BIND_PASSWORD = os.getenv('LDAP_BIND_PASSWORD')
AUTH_LDAP_USER_SEARCH = LDAPSearch(os.getenv('LDAP_USER_SEARCH_BASE_DN'), ldap.SCOPE_SUBTREE, "(uid=%(user)s)")

# Optional: Group settings
AUTH_LDAP_GROUP_SEARCH = LDAPSearch(os.getenv('LDAP_GROUP_SEARCH_BASE_DN'), ldap.SCOPE_SUBTREE, "(objectClass=posixGroup)")
AUTH_LDAP_GROUP_TYPE = PosixGroupType()
AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    'is_active': "cn=active,ou=groups,dc=example,dc=com",
    'is_staff': "cn=staff,ou=groups,dc=example,dc=com",
    'is_superuser': "cn=superuser,ou=groups,dc=example,dc=com"
}

AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail"
}

# Optional: Configure LDAP caching
AUTH_LDAP_CACHE_GROUPS = True
AUTH_LDAP_GROUP_CACHE_TIMEOUT = 300
"""
        with open(settings_path, "a") as settings_file:
            settings_file.write(ldap_settings)

    @staticmethod
    def configure_logging(project_name):
        settings_path = f"{project_name}/{project_name}/settings.py"
        logging_settings = """
# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'logfile.log',
            'maxBytes': 10 * 1024 * 1024,  # 10M
            'backupCount': 5,
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
}
"""
        with open(settings_path, "a") as settings_file:
            settings_file.write(logging_settings)

    @staticmethod
    def add_django_rest_framework_settings(project_name):
        settings_path = f"{project_name}/{project_name}/settings.py"
        with open(settings_path, "r") as file:
            original_content = file.read()

        # Ensure 'from datetime import timedelta' is present
        if "from datetime import timedelta" not in original_content:
            original_content = "from datetime import timedelta\n" + original_content

        # Add 'rest_framework' to INSTALLED_APPS
        new_content = re.sub(
            r"(INSTALLED_APPS = \[)(.*?)(\])",
            r"\1\2    'rest_framework',\n\3",
            original_content,
            flags=re.DOTALL,
        )
        new_content = re.sub(
            r"(INSTALLED_APPS = \[)(.*?)(\])",
            r"\1\2    'rest_framework.authtoken',\n\3",
            new_content,
            flags=re.DOTALL,
        )
        new_content = re.sub(
            r"(INSTALLED_APPS = \[)(.*?)(\])",
            r"\1\2    'rest_framework_simplejwt',\n\3",
            new_content,
            flags=re.DOTALL,
        )
        new_content = re.sub(
            r"(INSTALLED_APPS = \[)(.*?)(\])",
            r"\1\2    'django_filters',\n\3",
            new_content,
            flags=re.DOTALL,
        )
        new_content = re.sub(
            r"(INSTALLED_APPS = \[)(.*?)(\])",
            r"\1\2    'drf_api_logger',\n\3",
            new_content,
            flags=re.DOTALL,
        )
        new_content = re.sub(
            r"(MIDDLEWARE = \[)(.*?)(\])",
            r"\1\2    'drf_api_logger.middleware.api_logger_middleware.APILoggerMiddleware',\n\3",
            new_content,
            flags=re.DOTALL,
        )

        # Add REST_FRAMEWORK settings
        rest_framework_config = """
# Rest Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly'
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
        # Package: djangorestframework-simplejwt
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
    ],
    'URL_FIELD_NAME': 'url',
}

# Simple JWT Settings
# https://django-rest-framework-simplejwt.readthedocs.io/en/latest/settings.html
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "UPDATE_LAST_LOGIN": False,

    "ALGORITHM": "HS256",
    "SIGNING_KEY": os.environ.get("SIMPLE_JWT_SECRET_KEY"),
    "VERIFYING_KEY": "",
    "AUDIENCE": None,
    "ISSUER": None,
    "JSON_ENCODER": None,
    "JWK_URL": None,
    "LEEWAY": 0,

    "AUTH_HEADER_TYPES": ("Bearer", "JWT", "Token"),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",

    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",

    "JTI_CLAIM": "jti",

    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),

    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSerializer",
    "TOKEN_VERIFY_SERIALIZER": "rest_framework_simplejwt.serializers.TokenVerifySerializer",
    "TOKEN_BLACKLIST_SERIALIZER": "rest_framework_simplejwt.serializers.TokenBlacklistSerializer",
    "SLIDING_TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainSlidingSerializer",
    "SLIDING_TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSlidingSerializer",
}


# Django Rest Framework Logging
# https://pypi.org/project/drf-api-logger/
DRF_API_LOGGER_DATABASE = True
DRF_API_LOGGER_EXCLUDE_KEYS = [
    'password',
    'token',
    'access',
    'refresh',
    'AUTHORIZATION',
]
"""
        new_content += rest_framework_config

        with open(settings_path, "w") as file:
            file.write(new_content)

    @staticmethod
    def add_swagger_settings(project_name):
        settings_path = f"{project_name}/{project_name}/settings.py"
        with open(settings_path, "r") as file:
            original_content = file.read()

        # Add 'drf_yasg' to INSTALLED_APPS
        new_content = re.sub(
            r"(INSTALLED_APPS = \[)(.*?)(\])",
            r"\1\2    'drf_yasg',\n\3",
            original_content,
            flags=re.DOTALL,
        )

        # Add REST_FRAMEWORK settings
        swagger_config = """
# Swagger settings
SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'basic': {
            'type': 'basic'
        },
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
        },
    },
    'SHOW_REQUEST_HEADERS': True,
    'APIS_SORTER': 'alpha',
    'LOGIN_URL': 'rest_framework:login',
    'LOGOUT_URL': 'rest_framework:logout',
}
"""
        new_content += swagger_config

        with open(settings_path, "w") as file:
            file.write(new_content)


class DjangoURLsConfigurer:
    @staticmethod
    def configure_urls(project_name):
        urls_path = f"{project_name}/{project_name}/urls.py"
        new_urls_file = """from django.contrib import admin
from django.urls import include, path, re_path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from rest_framework.authtoken import views
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

schema_view = get_schema_view(
   openapi.Info(
      title="Your Project API",
      default_version='v1',
      description="API documentation for your project",
      terms_of_service="https://www.yourproject.com/policies/terms/",
      contact=openapi.Contact(email="contact@yourproject.local"),
      license=openapi.License(name="Your Project License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

router = DefaultRouter()

urlpatterns = [
    path("admin/", admin.site.urls),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('api-token-auth/', views.obtain_auth_token, name='api-token-auth'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/', include(router.urls)),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
"""

        with open(urls_path, "w") as file:
            file.write(new_urls_file)


class CeleryConfigurer:
    @staticmethod
    def configure_celery(project_name):
        # Update settings.py to use environment variables for Celery configuration
        settings_path = f"{project_name}/{project_name}/settings.py"
        with open(settings_path, "r") as file:
            original_content = file.read()

        new_content = re.sub(
            r"(INSTALLED_APPS = \[)(.*?)(\])",
            r"\1\2    'django_celery_beat',\n\3",
            original_content,
            flags=re.DOTALL,
        )
        new_content = re.sub(
            r"(INSTALLED_APPS = \[)(.*?)(\])",
            r"\1\2    'django_celery_results',\n\3",
            new_content,
            flags=re.DOTALL,
        )

        celery_settings_config = """# Celery Configuration
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.environ.get(CELERY_BROKER_URL, 'redis://localhost:6379/0'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}
"""
        new_content += celery_settings_config

        with open(settings_path, "w") as file:
            file.write(new_content)

        # Create celery.py in the project directory
        celery_config = f"""from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', '{project_name}.settings')

app = Celery('{project_name}')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
"""
        celery_path = f"{project_name}/{project_name}/celery.py"
        with open(celery_path, "w") as celery_file:
            celery_file.write(celery_config)

        # Update __init__.py to import the Celery app
        init_path = f"{project_name}/{project_name}/__init__.py"
        with open(init_path, "a") as init_file:
            init_file.write(f"from .celery import app as celery_app\n\n")
            init_file.write("__all__ = ['celery_app']\n")


class DockerfileGenerator:
    @staticmethod
    def generate_dockerfile(project_name):
        # Updated Dockerfile to use Python 3.12.1-slim-bullseye
        dockerfile_content = f"""FROM python:3.12.1-slim-bullseye
ENV PYTHONUNBUFFERED 1

# Add system user and group
RUN addgroup --system django && adduser --system --ingroup django django

# Install LDAP dependencies
RUN apt-get update && apt-get install -y gcc libldap2-dev libsasl2-dev ldap-utils postgresql-client netcat && apt-get clean

RUN mkdir /code
WORKDIR /code
COPY . /code/
RUN pip install -r requirements.txt

# Add and give execution permissions to the entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Add and give execution permissions to the start scripts
COPY ./startscripts/* /startscripts/
RUN chmod +x /startscripts/*.sh

# Add static files directory
RUN mkdir static

# Update permissions
RUN chown -R django /code
USER django

# Run entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
EXPOSE 8000
"""
        # Adjust file paths as needed to ensure Docker context is set correctly
        with open(f"{project_name}/Dockerfile", "w") as dockerfile:
            dockerfile.write(dockerfile_content)

    @staticmethod
    def generate_entrypoint(project_name):
        entrypoint_content = f"""#!/bin/bash

set -e

while ! nc -z $DB_HOST $DB_PORT; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

>&2 echo "Postgres is up - executing command"
exec "$@"
"""
        # Adjust file paths as needed to ensure Docker context is set correctly
        with open(f"{project_name}/entrypoint.sh", "w") as entrypoint_file:
            entrypoint_file.write(entrypoint_content)

    @staticmethod
    def generate_startscripts(project_name):
        os.makedirs(f"{project_name}/startscripts", exist_ok=True)
        DockerfileGenerator.generate_startscript_web(project_name)
        DockerfileGenerator.generate_startscript_createsuperuser_web(project_name)
        DockerfileGenerator.generate_startscript_celery(project_name)
        DockerfileGenerator.generate_startscript_celery_beat(project_name)

    @staticmethod
    def generate_startscript_createsuperuser_web(project_name):
        createsuperuser_script_content = f"""from django.contrib.auth.models import User
from django.db.utils import IntegrityError
import os

try:
    User.objects.create_superuser(os.getenv('DJANGO_SUPERUSER_USERNAME'), os.getenv('DJANGO_SUPERUSER_EMAIL'), os.getenv('DJANGO_SUPERUSER_PASSWORD'))
except IntegrityError:
    pass
except Exception as e:
    print("An error occurred:", e)
"""

        with open(
            f"{project_name}/startscripts/createsuperuser_web.py", "w"
        ) as createsuperuser_web_file:
            createsuperuser_web_file.write(createsuperuser_script_content)

    @staticmethod
    def generate_startscript_web(project_name):
        startscript_content = f"""#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

# Synchronize the database with the current set of models and migrations
python manage.py makemigrations --noinput
python manage.py migrate --noinput

# Collect static files
python manage.py collectstatic --noinput

# Execute script to create users and add permissions
python manage.py shell < /startscripts/createsuperuser_web.py

# Import fixtures (if available)

# Start Django
# gunicorn --bind 0.0.0.0:8000 --workers 4 --max-requests 20 {project_name}.wsgi:application
python manage.py runserver 0.0.0.0:8000

"""

        with open(
            f"{project_name}/startscripts/startscript_web.sh", "w"
        ) as startscript_web_file:
            startscript_web_file.write(startscript_content)

    @staticmethod
    def generate_startscript_celery(project_name):
        startscript_content = f"""#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

echo "Waiting for Django..."

while ! nc -z $WEB_HOST 8000; do
    sleep 1
done

echo "Django started"

celery -A {project_name} worker --hostname={project_name}_worker --loglevel=info
"""

        with open(
            f"{project_name}/startscripts/startscript_celery.sh", "w"
        ) as startscript_celery_file:
            startscript_celery_file.write(startscript_content)

    @staticmethod
    def generate_startscript_celery_beat(project_name):
        startscript_content = f"""#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

echo "Waiting for Django..."

while ! nc -z $WEB_HOST 8000; do
    sleep 1
done

echo "Django started"

rm -f './celerybeat.pid'
celery -A {project_name} beat --loglevel=info --scheduler django_celery_beat.schedulers:DatabaseScheduler --pidfile=
"""

        with open(
            f"{project_name}/startscripts/startscript_celery_beat.sh", "w"
        ) as startscript_celery_beat_file:
            startscript_celery_beat_file.write(startscript_content)

    @staticmethod
    def generate_docker_compose(project_name):
        # docker-compose.yml with environment variables
        docker_compose_content = f"""version: '3'

services:
    db:
        container_name: {project_name}_db
        restart: always
        image: postgres
        env_file:
            - .env.production
    redis:
        container_name: {project_name}_redis
        restart: always
        image: "redis:alpine"
    web:
        container_name: {project_name}_web
        restart: always
        build: .
        command: /startscripts/startscript_web.sh
        volumes:
            - .:/{project_name}
        ports:
            - "8000:8000"
        env_file:
            - .env.production
        depends_on:
            - db
            - redis
    celery:
        container_name: {project_name}_celery
        restart: always
        build: .
        command: /startscripts/startscript_celery.sh
        volumes:
            - .:/{project_name}
        env_file:
            - .env.production
        depends_on:
            - db
            - redis
    beat:
        container_name: {project_name}_beat
        restart: always
        build: .
        command: /startscripts/startscript_celery_beat.sh
        volumes:
            - .:/{project_name}
        env_file:
            - .env.production
        depends_on:
            - db
            - redis
    flower:
        container_name: {project_name}_flower
        image: mher/flower
        command: celery flower
        env_file:
            - .env.production
        ports:
            - "5555:5555"
        depends_on:
            - redis
"""
        with open(f"{project_name}/docker-compose.yml", "w") as docker_compose:
            docker_compose.write(docker_compose_content)


def generate_secret_key():
    # Django's secret key consists of 50 characters from the given set
    chars = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)"
    return "".join(secrets.choice(chars) for _ in range(50))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage: python script.py <project_name> or python script.py --generate-secret-key"
        )
        sys.exit(1)

    if sys.argv[1] == "--generate-secret-key":
        secret_key = generate_secret_key()
        print(f"SECRET_KEY: {secret_key}")
        sys.exit(0)

    project_name = sys.argv[1]

    # VirtualEnvManager.create_virtual_env()
    PackageManager.install_packages()
    DjangoProjectCreator.create_project(project_name)
    SettingsConfigurer.configure_basic_settings(project_name)
    SettingsConfigurer.add_static_root(project_name)
    SettingsConfigurer.configure_database_settings(project_name)
    SettingsConfigurer.configure_logging(project_name)
    SettingsConfigurer.add_django_rest_framework_settings(project_name)
    SettingsConfigurer.add_swagger_settings(project_name)
    SettingsConfigurer.add_ldap_configuration(project_name)
    DjangoURLsConfigurer.configure_urls(project_name)
    CeleryConfigurer.configure_celery(project_name)
    DockerfileGenerator.generate_dockerfile(project_name)
    DockerfileGenerator.generate_entrypoint(project_name)
    DockerfileGenerator.generate_startscripts(project_name)
    DockerfileGenerator.generate_docker_compose(project_name)
    PackageManager.freeze_packages(project_name)
    EnvFileGenerator.generate_env_files(project_name)
    EnvFileGenerator.add_postgres_env_variables(project_name)
    EnvFileGenerator.add_celery_env_variables(project_name)
    EnvFileGenerator.add_ldap_env_variables(project_name)
