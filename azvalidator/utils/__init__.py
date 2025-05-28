from datetime import datetime, timedelta, timezone

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
def generate_app_azure_token() -> str:
    """
    Autentica uma aplicação no Azure AD utilizando o fluxo client_credentials.
    Permite que a aplicação se comunique com outras aplicações protegidas.

    Returns:
        str: Token de acesso válido.

    Raises:
        ImproperlyConfigured: Se alguma variável de ambiente necessária não estiver configurada.
    """
    required_settings = [
        "AZURE_AD_URL",
        "AZURE_AD_TENANT_ID",
        "AZURE_AD_APP_GRANT_TYPE",
        "AZURE_AD_APP_CLIENT_ID",
        "AZURE_AD_APP_CLIENT_SECRET",
        "AZURE_AD_APP_SCOPE",
    ]

    for setting in required_settings:
        if not getattr(settings, setting, None):
            raise ImproperlyConfigured(f"A variável de ambiente '{setting}' não está configurada.")

    url = f"{settings.AZURE_AD_URL}/{settings.AZURE_AD_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": settings.AZURE_AD_APP_GRANT_TYPE,
        "client_id": settings.AZURE_AD_APP_CLIENT_ID,
        "client_secret": settings.AZURE_AD_APP_CLIENT_SECRET,
        "scope": settings.AZURE_AD_APP_SCOPE,
    }
    response = requests.post(url, data=data)
    response.raise_for_status()

    token_data = response.json()
    return token_data.get("access_token")