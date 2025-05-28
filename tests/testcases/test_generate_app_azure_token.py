import time
from unittest.mock import patch, MagicMock

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from azvalidator.utils import generate_app_azure_token

CACHE_KEY_TOKEN = "azure_ad_token"
CACHE_KEY_EXPIRES_AT = "azure_ad_token_expires_at"


class GenerateAppAzureTokenTests(TestCase):
    def setUp(self):
        cache.clear()  # limpa cache antes de cada teste

    def tearDown(self):
        cache.clear()  # limpa cache após teste

    @patch("azvalidator.utils.settings")
    @patch("azvalidator.utils.requests.post")
    def test_generate_token_success(self, mock_post, mock_settings):
        """Testa se o token é gerado corretamente ao chamar a função."""
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

        # Verifica se token está no cache
        cached_token = cache.get(CACHE_KEY_TOKEN)
        self.assertEqual(cached_token, "mock_token")

    @patch("azvalidator.utils.settings")
    def test_missing_required_settings(self, mock_settings):
        """Testa se a função levanta ImproperlyConfigured quando falta configuração."""
        mock_settings.AZURE_AD_URL = None
        with self.assertRaises(ImproperlyConfigured):
            generate_app_azure_token()

    @patch("azvalidator.utils.settings")
    @patch("azvalidator.utils.requests.post")
    def test_generate_token_with_cache(self, mock_post, mock_settings):
        """Testa se o cache é utilizado corretamente e evita chamadas desnecessárias à API."""
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

        token1 = generate_app_azure_token()
        self.assertEqual(token1, "mock_token")
        mock_post.assert_called_once()

        # Segunda chamada deve usar o cache e não chamar a API novamente
        token2 = generate_app_azure_token()
        self.assertEqual(token2, "mock_token")
        mock_post.assert_called_once()  # nenhuma nova chamada

    @patch("azvalidator.utils.settings")
    @patch("azvalidator.utils.requests.post")
    def test_generate_token_expired_fetches_new(self, mock_post, mock_settings):
        """Testa se um novo token é buscado quando o token anterior expira."""
        mock_settings.AZURE_AD_URL = "https://example.com"
        mock_settings.AZURE_AD_TENANT_ID = "tenant_id"
        mock_settings.AZURE_AD_APP_GRANT_TYPE = "client_credentials"
        mock_settings.AZURE_AD_APP_CLIENT_ID = "client_id"
        mock_settings.AZURE_AD_APP_CLIENT_SECRET = "client_secret"
        mock_settings.AZURE_AD_APP_SCOPE = "scope"

        mock_response1 = MagicMock()
        mock_response1.json.return_value = {
            "access_token": "mock_token_1",
            "expires_in": 1,
        }
        mock_response1.raise_for_status = MagicMock()

        mock_response2 = MagicMock()
        mock_response2.json.return_value = {
            "access_token": "mock_token_2",
            "expires_in": 3600,
        }
        mock_response2.raise_for_status = MagicMock()

        mock_post.side_effect = [mock_response1, mock_response2]

        token1 = generate_app_azure_token()
        self.assertEqual(token1, "mock_token_1")

        time.sleep(1.1)  # Espera expirar o token no cache

        token2 = generate_app_azure_token()
        self.assertEqual(token2, "mock_token_2")
        self.assertEqual(mock_post.call_count, 2)

    @patch("azvalidator.utils.settings")
    @patch("azvalidator.utils.requests.post")
    def test_generate_token_not_expired_reuses_token(self, mock_post, mock_settings):
        """
        Testa se o token é reutilizado se ainda não expirou.
        """
        mock_settings.AZURE_AD_URL = "https://example.com"
        mock_settings.AZURE_AD_TENANT_ID = "tenant_id"
        mock_settings.AZURE_AD_APP_GRANT_TYPE = "client_credentials"
        mock_settings.AZURE_AD_APP_CLIENT_ID = "client_id"
        mock_settings.AZURE_AD_APP_CLIENT_SECRET = "client_secret"
        mock_settings.AZURE_AD_APP_SCOPE = "scope"

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "mock_token",
            "expires_in": 3600,  # tempo longo para cache não expirar
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        # Chamada 1: faz a requisição real (mockada) e armazena no cache
        token1 = generate_app_azure_token()
        self.assertEqual(token1, "mock_token")
        self.assertEqual(mock_post.call_count, 1)

        # Resetamos mocks para garantir que nova chamada será detectada
        mock_post.reset_mock()

        # Chamada 2: deve retornar token do cache e não chamar requests.post
        token2 = generate_app_azure_token()
        self.assertEqual(token2, "mock_token")
        self.assertEqual(mock_post.call_count, 0)  # nenhuma nova chamada HTTP
