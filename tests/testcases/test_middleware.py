from django.test import TestCase, Client, override_settings
import jwt
from datetime import datetime, timedelta, timezone

AZURE_SETTINGS = {
    "AZURE_AD_URL": "https://example.com",  # Dummy URL
    "AZURE_AD_TENANT_ID": "tenant-id",  # Dummy URL
    "AZURE_AD_CLIENT_ID": "api://dummy-client-id",
    "AZURE_AD_VERIFY_SIGNATURE": False,  # Desativa verificação para testes
    "AZURE_AD_USER_APPLICATION": "test_app",
    "AZURE_AD_ROLE_APPLICATION": "TestAppRole",
}


@override_settings(**AZURE_SETTINGS)
class MiddlewareIntegrationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.secret = "dummy-secret"
        self.tenant_id = AZURE_SETTINGS["AZURE_AD_TENANT_ID"]
        self.client_id = AZURE_SETTINGS["AZURE_AD_CLIENT_ID"]

    def _generate_token(self, claims=None):
        now = datetime.now(timezone.utc)
        if claims is None:
            claims = {
                "preferred_username": "john.doe@example.com",
                "aud": self.client_id,
                "iss": self.tenant_id,
                "exp": int((now + timedelta(hours=1)).timestamp()),
            }
        return jwt.encode(claims, self.secret, algorithm="HS256")

    def test_request_without_token_returns_401(self):
        """Deve retornar 401 se o token estiver ausente."""
        response = self.client.get("/dummy/")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Token", response.json()["error"])

    def test_request_with_invalid_token_returns_401(self):
        """Deve retornar 401 se o token for malformado ou inválido."""
        response = self.client.get("/dummy/", HTTP_AUTHORIZATION="Bearer token_invalido")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Token inválido", response.json()["error"])

    def test_request_to_unprotected_view_returns_200(self):
        """Testa que uma view desprotegida (sem azure_authentication) responde normalmente."""
        with override_settings(MIDDLEWARE=[]):
            response = self.client.get("/dummy/")
            self.assertEqual(response.status_code, 200)

    def test_request_with_valid_token_returns_200(self):
        """Deve retornar 200 e injetar o username quando o token é válido."""
        token = self._generate_token()
        response = self.client.get("/dummy/", HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"], "john.doe")  # era "john.doe@example.com"
        self.assertEqual(response.json()["email"], "john.doe@example.com")  # agora você pode validar o e-mail

    def test_request_with_token_missing_username_returns_401(self):
        """Deve retornar 401 se o token não possuir 'preferred_username'."""
        token = self._generate_token(
            {
                "aud": self.client_id,
                "iss": self.tenant_id,
                "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
                "upn": "test user",
            }
        )
        response = self.client.get("/dummy/", HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(response.status_code, 401)
        self.assertIn("preferred_username", response.json()["error"])
