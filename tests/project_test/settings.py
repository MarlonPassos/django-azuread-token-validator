import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

sys.path.insert(0, os.path.abspath(os.path.join(BASE_DIR, "..")))

SECRET_KEY = "fake"
DEBUG = True

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "azvalidator",
]

MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
    'azvalidator.middleware.AzureADTokenValidatorMiddleware',
]


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}


ALLOWED_HOSTS = ["*"]

ROOT_URLCONF = "project_test.urls"
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

AZURE_AD_JWKS_URL = "https://login.microsoftonline.com/common/discovery/keys"
AZURE_AD_ISSUER_URL = "https://login.microsoftonline.com/common/v2.0"
AZURE_AD_AUDIENCE = "api://test-client-id"
AZURE_AD_ALGORITHMS = ["RS256"]
AZURE_AD_VERIFY_SIGNATURE = False  # Para teste, pode desligar assinatura para facilitar
