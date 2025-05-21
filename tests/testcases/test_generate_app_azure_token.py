from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from azvalidator.utils import generate_app_azure_token


class GenerateAppAzureTokenTests(TestCase):
    @patch("azvalidator.utils.settings")
    @patch("azvalidator.utils.requests.post")
    def test_generate_token_success(self, mock_post, mock_settings):
        """
        Testa se o token é gerado corretamente quando não há um token válido no cache.
        Simula uma resposta bem-sucedida da API e verifica se o token gerado
        corresponde ao esperado e se o cache é atualizado corretamente.
        """
        generate_app_azure_token.__globals__["_token_cache"] = {
            "access_token": None,
            "expires_at": None,
        }

        mock_settings.AZURE_AD_URL = "https://example.com"
        mock_settings.AZURE_AD_TENANT_ID = "tenant_id"
        mock_settings.AZURE_AD_APP_GRANT_TYPE = "client_credentials"
        mock_settings.AZURE_AD_APP_CLIENT_ID = "client_id"
        mock_settings.AZURE_AD_APP_CLIENT_SECRET = "client_secret"
        mock_settings.AZURE_AD_APP_SCOPE = "scope"

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "mock_token",
            "expires_in": 3600,
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        token = generate_app_azure_token()

        self.assertEqual(token, "mock_token")
        self.assertIn("access_token", generate_app_azure_token.__globals__["_token_cache"])
        self.assertIn("expires_at", generate_app_azure_token.__globals__["_token_cache"])

    @patch("azvalidator.utils.settings")
    def test_missing_required_settings(self, mock_settings):
        """
        Testa se a função levanta uma exceção ImproperlyConfigured
        quando uma configuração obrigatória está ausente.
        """
        mock_settings.AZURE_AD_URL = None

        with self.assertRaises(ImproperlyConfigured):
            generate_app_azure_token()

    @patch("azvalidator.utils.settings")
    @patch("azvalidator.utils.requests.post")
    def test_cached_token(self, mock_post, mock_settings):
        """
        Testa se a função retorna o token armazenado no cache
        quando ele ainda é válido, sem realizar uma nova requisição à API.
        """
        generate_app_azure_token.__globals__["_token_cache"] = {
            "access_token": "cached_token",
            "expires_at": datetime.now(timezone.utc) + timedelta(seconds=3600),
        }

        token = generate_app_azure_token()

        self.assertEqual(token, "cached_token")
        mock_post.assert_not_called()

    @patch("azvalidator.utils.settings")
    @patch("azvalidator.utils.requests.post")
    def test_expired_token(self, mock_post, mock_settings):
        """
        Testa se a função renova o token quando o token armazenado no cache
        está expirado. Simula uma resposta bem-sucedida da API e verifica
        se o novo token é retornado e o cache é atualizado.
        """
        generate_app_azure_token.__globals__["_token_cache"] = {
            "access_token": "expired_token",
            "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
        }

        mock_settings.AZURE_AD_URL = "https://example.com"
        mock_settings.AZURE_AD_TENANT_ID = "tenant_id"
        mock_settings.AZURE_AD_APP_GRANT_TYPE = "client_credentials"
        mock_settings.AZURE_AD_APP_CLIENT_ID = "client_id"
        mock_settings.AZURE_AD_APP_CLIENT_SECRET = "client_secret"
        mock_settings.AZURE_AD_APP_SCOPE = "scope"

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new_token",
            "expires_in": 3600,
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        token = generate_app_azure_token()

        self.assertEqual(token, "new_token")
        mock_post.assert_called_once()