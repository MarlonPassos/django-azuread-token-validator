import logging

import jwt
import requests
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from jwt import PyJWKClient, PyJWKClientError

from azvalidator.utils import generate_app_azure_token

logger = logging.getLogger(__name__)

# TODO: Configurar cache de JWK e UserInfo
# AZURE_AD_AUX_USERINFO_CACHE_TIMEOUT = 3600  # 1 hora

try:
    TENANT_ID = settings.AZURE_AD_TENANT_ID
    AZURE_URL = settings.AZURE_AD_URL
    JWKS_URL = f"{AZURE_URL}/{TENANT_ID}/discovery/keys"
    # cache_keys=True ativa o cache interno, lifespan define a validade do cache.
    jwk_client = PyJWKClient(JWKS_URL, cache_keys=True, lifespan=3600)
    logger.info("Cliente JWK do Azure AD inicializado com cache.")
except (AttributeError, ImproperlyConfigured):
    jwk_client = None
    logger.error("Configurações do Azure AD não encontradas. A validação de token não funcionará.")
except Exception as e:
    jwk_client = None
    logger.error(f"Falha ao inicializar o cliente JWK do Azure AD: {e}")


class AzureADTokenValidatorMiddleware:
    """
    Middleware to validate Azure AD JWT tokens and enrich request with user profile data.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self._load_settings()
        if not jwk_client and self.verify_signature:
            raise ImproperlyConfigured("Cliente JWK para validação de token do Azure não pôde ser inicializado.")

    def _load_settings(self):
        self.azure_url: str = getattr(settings, "AZURE_AD_URL", None)
        self.tenant_id: str = getattr(settings, "AZURE_AD_TENANT_ID", None)
        self.client_id: str = getattr(settings, "AZURE_AD_CLIENT_ID", None)
        self.verify_signature: bool = getattr(settings, "AZURE_AD_VERIFY_SIGNATURE", True)
        self.algorithms: list[str] = getattr(settings, "AZURE_AD_ALGORITHMS", ["RS256"])

        if not self.tenant_id or not self.azure_url or not self.client_id:
            raise ImproperlyConfigured("Parâmetros obrigatórios do Azure AD não configurados.")

        self.extra_user_info_url: str | None = getattr(settings, "AZURE_AD_AUX_USERINFO_SERVICE_URL", None)
        self.extra_user_info_timeout: int = getattr(settings, "AZURE_AD_AUX_USERINFO_SERVICE_TIMEOUT", 10)
        self.extra_user_info_mapping: dict = getattr(
            settings,
            "AZURE_AD_AUX_USERINFO_MAPPING",
            {
                "department": "azure_department",
                "department_number": "azure_department_number",
                "company": "azure_company",
                "employee_number": "azure_employee_role",
            },
        )

        self.default_app_username = getattr(settings, "AZURE_AD_DEFAULT_APP_USERNAME", "app")
        self.default_app_role = getattr(settings, "AZURE_AD_DEFAULT_APP_ROLE", "AppRole")
        self.cache_user_info_timeout = getattr(settings, "AZURE_AD_AUX_USERINFO_CACHE_TIMEOUT", 3600)

    def __call__(self, request):
        return self.get_response(request)

    def _extract_token_from_header(self, request) -> str | None:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header.split(" ", 1)[1]
        return None

    def process_view(self, request, view_func, view_args, view_kwargs):
        view_class = getattr(view_func, "cls", None)
        if not (view_class and getattr(view_class, "azure_authentication", False)):
            return None

        token = self._extract_token_from_header(request)
        if not token:
            return self._unauthorized("Token não fornecido ou mal formatado.")

        try:
            if self.verify_signature:
                signing_key = jwk_client.get_signing_key_from_jwt(token)
                key = signing_key.key
            else:
                key = None  # Não valida a assinatura

            issuer_url = f"{self.azure_url}/{self.tenant_id}/v2.0"
            decoded_token = jwt.decode(
                token,
                key=key,
                algorithms=self.algorithms,
                audience=self.client_id,
                issuer=issuer_url,
                options={"verify_signature": self.verify_signature},
            )

            # Enriquecimento do request
            if self._is_client_credentials_token(decoded_token):
                username = self.default_app_username
                roles = [self.default_app_role]
                email = None
            else:
                username = decoded_token.get("preferred_username", None)
                if not username:
                    return self._unauthorized("Token não contém 'preferred_username'.")

                email = username
                roles = decoded_token.get("roles", [])
                username = username.split("@")[0] if username else ""

            request.azure_username = username
            request.azure_roles = roles
            request.azure_email = email
            request.userinfo = decoded_token

            if self.extra_user_info_url and username and not self._is_client_credentials_token(decoded_token):
                user_info = self._fetch_additional_user_info(username)
                for field, attr in self.extra_user_info_mapping.items():
                    setattr(request, attr, user_info.get(field, None))

            request.userinfo = decoded_token

        except jwt.ExpiredSignatureError:
            return self._unauthorized("Token expirado.")
        except jwt.InvalidAudienceError:
            return self._unauthorized("Audiência inválida.")
        except jwt.InvalidIssuerError:
            return self._unauthorized("Emissor inválido.")
        except jwt.InvalidTokenError as e:
            return self._unauthorized(f"Token inválido: {e}")
        except PyJWKClientError as e:
            return self._server_error(f"Erro ao buscar chave pública: {e}")
        except Exception as e:
            return self._server_error(f"Erro inesperado na validação do token: {e}")

        return None

    def _is_client_credentials_token(self, decoded: dict) -> bool:
        return "upn" not in decoded and "preferred_username" not in decoded

    def _fetch_additional_user_info(self, username: str) -> dict:
        cache_key = f"azure_userinfo::{username}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        userinfo_token = generate_app_azure_token()
        headers = {"Authorization": f"Bearer {userinfo_token}"} if userinfo_token else {}
        url = f"{self.extra_user_info_url.rstrip('/')}/{username}/"

        try:
            response = requests.get(url, headers=headers, timeout=self.extra_user_info_timeout)
            response.raise_for_status()
            data = response.json()
            cache.set(cache_key, data, timeout=self.cache_user_info_timeout)
            return data
        except requests.RequestException as e:
            logger.error(f"Erro ao buscar dados adicionais para '{username}': {e}")
            return {}

    def _unauthorized(self, message: str):
        logger.warning(message)
        return JsonResponse({"error": message}, status=401)

    def _server_error(self, message: str):
        logger.error(message)
        return JsonResponse({"error": message}, status=500)
