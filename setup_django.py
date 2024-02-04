#!/usr/bin/python3
import subprocess
import re
import secrets
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
                "redis",
                "django-auth-ldap",
                "django-rest-framework",
                "drf-yasg",
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
            "development": """
ALLOWED_HOSTS=*
SECRET_KEY=your_secret_key_development
DEBUG=True

""",
            "production": """
ALLOWED_HOSTS=*
SECRET_KEY=your_secret_key_production
DEBUG=False

""",
        }

        for env, content in env_content.items():
            with open(f"{project_name}/.env.{env}", "w") as env_file:
                env_file.write(content.strip())

    @staticmethod
    def add_celery_env_variables(project_name):
        celery_env_variables = """
# CELERY Configuration
CELERY_BROKER_URL=redis://your_redis_host:6379/0
CELERY_RESULT_BACKEND=redis://your_redis_host:6379/0
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
DB_HOST=localhost
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
        with open(settings_path, 'r') as file:
            original_content = file.read()

        # Add 'rest_framework' to INSTALLED_APPS
        new_content = re.sub(r"(INSTALLED_APPS = \[)(.*?)(\])", r"\1\2    'rest_framework',\n\3", original_content, flags=re.DOTALL)
        new_content = re.sub(r"(INSTALLED_APPS = \[)(.*?)(\])", r"\1\2    'rest_framework.authtoken',\n\3", new_content, flags=re.DOTALL)

        # Add REST_FRAMEWORK settings
        rest_framework_config = """
# Rest Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissionsOrAnonReadOnly'
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication'
    ],
}
"""
        new_content += rest_framework_config

        with open(settings_path, 'w') as file:
            file.write(new_content)

    @staticmethod
    def add_swagger_settings(project_name):
        settings_path = f"{project_name}/{project_name}/settings.py"
        with open(settings_path, 'r') as file:
            original_content = file.read()

        # Add 'drf_yasg' to INSTALLED_APPS
        new_content = re.sub(r"(INSTALLED_APPS = \[)(.*?)(\])", r"\1\2    'drf_yasg',\n\3", original_content, flags=re.DOTALL)

        # Add REST_FRAMEWORK settings
        swagger_config = """
# Swagger settings
SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'basic': {
            'type': 'basic'
        }
    },
}
"""
        new_content += swagger_config

        with open(settings_path, 'w') as file:
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
    path('api/', include(router.urls)),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
"""

        with open(urls_path, 'w') as file:
            file.write(new_urls_file)


class CeleryConfigurer:
    @staticmethod
    def configure_celery(project_name):
        # Update settings.py to use environment variables for Celery configuration
        settings_path = f"{project_name}/{project_name}/settings.py"
        with open(settings_path, "a") as settings_file:
            settings_file.write("\n# Celery Configuration\n")
            settings_file.write(
                "CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')\n"
            )
            settings_file.write(
                "CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')\n"
            )
            settings_file.write("CELERY_ACCEPT_CONTENT = ['application/json']\n")
            settings_file.write("CELERY_TASK_SERIALIZER = 'json'\n")
            settings_file.write("CELERY_RESULT_SERIALIZER = 'json'\n")

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
            init_file.write(f"from .celery import app as celery_app\n")


class DockerfileGenerator:
    @staticmethod
    def generate_docker_files(project_name):
        # Updated Dockerfile to use Python 3.12.1-slim-bullseye
        dockerfile_content = f"""FROM python:3.12.1-slim-bullseye
ENV PYTHONUNBUFFERED 1

# Install LDAP dependencies
RUN apt-get update && apt-get install -y gcc libldap2-dev libsasl2-dev ldap-utils && apt-get clean

RUN mkdir /code
WORKDIR /code
COPY . /code/
RUN pip install -r requirements.txt
"""
        # Adjust file paths as needed to ensure Docker context is set correctly
        with open(f"{project_name}/Dockerfile", "w") as dockerfile:
            dockerfile.write(dockerfile_content)

        # docker-compose.yml with environment variables
        docker_compose_content = f"""version: '3'

services:
  db:
    image: postgres
    env_file:
      - .env.production
  redis:
    image: "redis:alpine"
  web:
    build: .
    command: python manage.py runserver 0.0.0.0:8000
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
    build: .
    command: celery -A {project_name} worker --loglevel=info
    volumes:
      - .:/{project_name}
    env_file:
      - .env.production
    depends_on:
      - db
      - redis
  beat:
    build: .
    command: celery -A {project_name} beat --loglevel=info
    volumes:
      - .:/{project_name}
    env_file:
      - .env.production
    depends_on:
      - db
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
    SettingsConfigurer.configure_database_settings(project_name)
    SettingsConfigurer.configure_logging(project_name)
    SettingsConfigurer.add_django_rest_framework_settings(project_name)
    SettingsConfigurer.add_swagger_settings(project_name)
    SettingsConfigurer.add_ldap_configuration(project_name)
    DjangoURLsConfigurer.configure_urls(project_name)
    CeleryConfigurer.configure_celery(project_name)
    DockerfileGenerator.generate_docker_files(project_name)
    PackageManager.freeze_packages(project_name)
    EnvFileGenerator.generate_env_files(project_name)
    EnvFileGenerator.add_postgres_env_variables(project_name)
    EnvFileGenerator.add_celery_env_variables(project_name)
    EnvFileGenerator.add_ldap_env_variables(project_name)
