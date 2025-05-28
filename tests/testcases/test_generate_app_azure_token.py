from unittest.mock import patch, MagicMock

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from azvalidator.utils import generate_app_azure_token


class GenerateAppAzureTokenTests(TestCase):
    @patch("azvalidator.utils.settings")
    @patch("azvalidator.utils.requests.post")
    def test_generate_token_success(self, mock_post, mock_settings):
        """
        Testa se o token é gerado corretamente ao chamar a função.
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
            "expires_in": 3600,
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        token = generate_app_azure_token()
        self.assertEqual(token, "mock_token")

    @patch("azvalidator.utils.settings")
    def test_missing_required_settings(self, mock_settings):
        """
        Testa se a função levanta ImproperlyConfigured quando falta configuração.
        """
        mock_settings.AZURE_AD_URL = None
        with self.assertRaises(ImproperlyConfigured):
            generate_app_azure_token()