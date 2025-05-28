import logging
from datetime import datetime, timedelta, timezone

import requests
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

CACHE_KEY_TOKEN = "azure_ad_token"
CACHE_KEY_EXPIRES_AT = "azure_ad_token_expires_at"


def generate_app_azure_token() -> str:
    """
    Autentica uma aplicação no Azure AD utilizando o fluxo client_credentials.
    Garante que o token não esteja expirado antes de retornar.
    Usa cache do Django para armazenar o token e sua expiração.
    """
    now = datetime.now(timezone.utc)

    token = cache.get(CACHE_KEY_TOKEN)
    expires_at_str = cache.get(CACHE_KEY_EXPIRES_AT)

    expires_at = None
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except Exception as e:
            logger.warning(f"Erro ao converter expires_at do cache: {e}")
            expires_at = None

    if token and expires_at and now < expires_at - timedelta(seconds=120):
        return token

    required_settings = [
        "AZURE_AD_URL",
        "AZURE_AD_TENANT_ID",
        "AZURE_AD_APP_GRANT_TYPE",
        "AZURE_AD_APP_CLIENT_ID",
        "AZURE_AD_APP_CLIENT_SECRET",
        "AZURE_AD_APP_SCOPE",
    ]

    missing = [s for s in required_settings if not getattr(settings, s, None)]
    if missing:
        msg = f"A variável de ambiente(s) '{', '.join(missing)}' não está(ão) configurada(s)."
        logger.error(msg)
        raise ImproperlyConfigured(msg)

    url = f"{settings.AZURE_AD_URL.rstrip('/')}/{settings.AZURE_AD_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": settings.AZURE_AD_APP_GRANT_TYPE,
        "client_id": settings.AZURE_AD_APP_CLIENT_ID,
        "client_secret": settings.AZURE_AD_APP_CLIENT_SECRET,
        "scope": settings.AZURE_AD_APP_SCOPE,
    }

    try:
        response = requests.post(url, data=data, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Erro ao obter token do Azure AD: {e}")
        raise RuntimeError("Erro ao obter token do Azure AD") from e

    try:
        token_data = response.json()
    except Exception as e:
        logger.error(f"Erro ao decodificar resposta JSON da API de token Azure AD: {e}")
        raise RuntimeError("Resposta inválida da API de token Azure AD") from e

    access_token = token_data.get("access_token")
    if not access_token:
        logger.error("Resposta da API de token Azure AD não contém 'access_token'")
        raise RuntimeError("Resposta da API não contém 'access_token'")

    expires_in = token_data.get("expires_in")
    if not expires_in:
        logger.error("Resposta da API de token Azure AD não contém 'expires_in'")
        raise RuntimeError("Resposta da API não contém 'expires_in'")

    expires_at = now + timedelta(seconds=max(expires_in - 120, 60))  # 120s de margem

    cache_timeout = max(expires_in - 120, 60)

    # Armazena no cache: token e expiração (como string ISO)
    cache.set(CACHE_KEY_TOKEN, access_token, timeout=cache_timeout)
    cache.set(CACHE_KEY_EXPIRES_AT, expires_at.isoformat(), timeout=cache_timeout)

    logger.info(f"Token gerado com sucesso. Expira em {expires_at.isoformat()}")

    return access_token
