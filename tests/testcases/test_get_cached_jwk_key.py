from unittest.mock import patch, MagicMock
from django.core.cache import cache
from django.test import TestCase
from jwt import PyJWKClientError

from azvalidator.middleware import get_cached_jwk_key


class GetCachedJWKKeyTests(TestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    @patch("azvalidator.middleware.PyJWKClient")
    def test_fetch_key_and_cache(self, mock_jwk_client_class):
        """Testa se a chave JWK é buscada e armazenada em cache"""
        mock_key = MagicMock()
        mock_key.key = "public_key_mock"

        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = mock_key
        mock_jwk_client_class.return_value = mock_client

        jwk_url = "https://login.microsoftonline.com/common/discovery/keys"
        token = "mock.token.value"

        # Primeira chamada deve buscar e armazenar no cache
        key1 = get_cached_jwk_key(jwk_url, token)
        self.assertEqual(key1, "public_key_mock")
        mock_client.get_signing_key_from_jwt.assert_called_once_with(token)

        # Segunda chamada deve usar o cache, não chamar novamente
        mock_client.get_signing_key_from_jwt.reset_mock()
        key2 = get_cached_jwk_key(jwk_url, token)
        self.assertEqual(key2, "public_key_mock")
        mock_client.get_signing_key_from_jwt.assert_not_called()

    @patch("azvalidator.middleware.PyJWKClient")
    def test_fetch_key_failure(self, mock_jwk_client_class):
        """Testa se erro na busca da JWK levanta RuntimeError"""
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.side_effect = PyJWKClientError("JWK failed")
        mock_jwk_client_class.return_value = mock_client

        with self.assertRaises(RuntimeError) as ctx:
            get_cached_jwk_key("https://login.microsoft.com/keys", "invalid.token")
        self.assertIn("Erro ao buscar JWK", str(ctx.exception))

    @patch("azvalidator.middleware.PyJWKClient")
    def test_cache_timeout_behavior(self, mock_jwk_client_class):
        """Testa se chave é buscada novamente após cache ser limpo (simulando expiração)."""
        mock_key1 = MagicMock()
        mock_key1.key = "public_key_1"

        mock_key2 = MagicMock()
        mock_key2.key = "public_key_2"

        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.side_effect = [mock_key1, mock_key2]
        mock_jwk_client_class.return_value = mock_client

        jwk_url = "https://login.microsoft.com/keys"
        token = "test.token"

        # Primeira chamada — armazena no cache
        key1 = get_cached_jwk_key(jwk_url, token)
        self.assertEqual(key1, "public_key_1")

        # Simula expiração do cache removendo manualmente
        cache.delete(f"azure_jwk::{jwk_url}::{token[:10]}")

        # Segunda chamada — busca novamente (novo valor)
        key2 = get_cached_jwk_key(jwk_url, token)
        self.assertEqual(key2, "public_key_2")
