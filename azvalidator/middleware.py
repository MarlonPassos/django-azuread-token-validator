import logging
import jwt
import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from jwt import PyJWKClient, PyJWKClientError

logger = logging.getLogger(__name__)


class AzureADTokenValidatorMiddleware:
    """
    Middleware to validate Azure AD JWT tokens and enrich request with user profile data.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self._load_settings()

    def _load_settings(self):
        self.jwks_url: str = getattr(settings, "AZURE_AD_JWKS_URL", None)
        self.verify_signature: bool = getattr(settings, "AZURE_AD_VERIFY_SIGNATURE", True)
        self.issuer_url: str = getattr(settings, "AZURE_AD_ISSUER_URL", None)
        self.audience: str = getattr(settings, "AZURE_AD_AUDIENCE", None)
        self.algorithms: list[str] = getattr(settings, "AZURE_AD_ALGORITHMS", ["RS256"])

        if not self.jwks_url or not self.issuer_url or not self.audience:
            raise ImproperlyConfigured("Parâmetros obrigatórios do Azure AD não configurados.")

        self.extra_user_info_url: str | None = getattr(settings, "AZURE_AD_AUX_USERINFO_SERVICE_URL", None)
        self.extra_user_info_token: str | None = getattr(settings, "AZURE_AD_AUX_USERINFO_SERVICE_TOKEN", None)
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
                signing_key = PyJWKClient(self.jwks_url).get_signing_key_from_jwt(token)
                key = signing_key.key
            else:
                key = None  # Não valida a assinatura

            decoded_token = jwt.decode(
                token,
                key=key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer_url,
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
        headers = {"Authorization": f"Bearer {self.extra_user_info_token}"} if self.extra_user_info_token else {}
        url = f"{self.extra_user_info_url.rstrip('/')}/{username}/"
        try:
            response = requests.get(url, headers=headers, timeout=self.extra_user_info_timeout)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Erro ao buscar dados adicionais para '{username}': {e}")
            return {}

    def _unauthorized(self, message: str):
        logger.warning(message)
        return JsonResponse({"error": message}, status=401)

    def _server_error(self, message: str):
        logger.error(message)
        return JsonResponse({"error": message}, status=500)
