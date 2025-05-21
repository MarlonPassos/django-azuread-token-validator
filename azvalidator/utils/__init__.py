from datetime import datetime, timedelta, timezone

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

_token_cache = {
    "access_token": None,
    "expires_at": None,
}


def generate_app_azure_token() -> str:
    """
    Autentica uma aplicação no Azure AD utilizando o fluxo client_credentials.
    Permite que a aplicação se comunique com outras aplicações protegidas.

    A função armazena o token de acesso em cache e o renova automaticamente
    quando necessário.

    Returns:
        str: Token de acesso válido.

    Raises:
        ImproperlyConfigured: Se alguma variável de ambiente necessária não estiver configurada.
    """
    global _token_cache

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

    if _token_cache["access_token"] and _token_cache["expires_at"] > datetime.now(timezone.utc):
        return _token_cache["access_token"]

    url = f"{settings.AZURE_AD_URL}/{settings.AZURE_AD_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": settings.AZURE_AD_APP_GRANT_TYPE,
        "client_id": settings.AZURE_AD_APP_CLIENT_ID,
        "client_secret": settings.AZURE_AD_APP_CLIENT_SECRET,
        "scope": settings.AZURE_AD_APP_SCOPE,
    }
    response = requests.post(url, data=data)
    response.raise_for_status()

    # Atualiza o cache com o novo token e sua expiração
    token_data = response.json()
    _token_cache["access_token"] = token_data.get("access_token")
    _token_cache["expires_at"] = datetime.now(timezone.utc) + timedelta(seconds=token_data.get("expires_in", 3600))

    return _token_cache["access_token"]