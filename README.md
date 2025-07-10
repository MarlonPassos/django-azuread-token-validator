
# django-azuread-token-validator (azvalidator)

Django middleware for validating JWT tokens issued by Azure AD and enriching the request object with additional user profile information. This middleware is designed exclusively for use with Django REST Framework (DRF) to securely and seamlessly protect API routes.

---

## Installation

You can install the package via pip directly from PyPI (or your private repository):

```bash
pip install django-azuread-token-validator
```

Or, if you prefer to install it from the local source code:

```bash
git clone https://github.com/MarlonPassos/django-azuread-token-validator.git
cd django-azuread-token-validator
pip install .
```

---

## Middleware Configuration

### 1. Add the middleware to your `settings.py`

Include the full path of the middleware in the `MIDDLEWARE` list:

```python
MIDDLEWARE = [
    # Default Django middlewares...
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',

    # Azure AD validation middleware
    'azvalidator.middleware.AzureADTokenValidatorMiddleware',  # adjust the path as needed

    # Other middlewares...
]
```

### 2. Environment variables for configuration

In `settings.py`, configure the following variables:

```python
# Azure AD authentication endpoint URL
AZURE_AD_URL = "https://login.microsoftonline.com"

# Azure AD JWKS endpoint URL (to fetch public verification keys) "https://login.microsoftonline.com/<tenant_id>/discovery/keys"
AZURE_AD_TENANT_ID = "<tenant_id>"

# Expected client_id  identifier in the JWT token (usually the audience or App ID URI)
AZURE_AD_CLIENT_ID = "api://<client_id>"

# JWKS cache timeout in seconds (default: 3600)
AZURE_AD_CACHE_TIMEOUT = 3600

# Enable or disable token signature verification (default: True)
AZURE_AD_VERIFY_SIGNATURE = True

# List of accepted JWT algorithms (default: ["RS256"])
AZURE_AD_ALGORITHMS = ["RS256"]

# Default username for Client Credentials tokens (app-to-app)
AZURE_AD_DEFAULT_APP_USERNAME = "app"

# Default role for Client Credentials tokens
AZURE_AD_DEFAULT_APP_ROLE = "AppRole"

# External service URL to fetch additional user information (optional)
# Configure client_credentials authentication needed
AZURE_AD_AUX_USERINFO_SERVICE_URL = "https://api.example.com/userinfo"

# Timeout for requests to the additional service in seconds (default: 10)
AZURE_AD_AUX_USERINFO_SERVICE_TIMEOUT = 10

# Time in seconds to cache the Azure AD JWKS (JSON Web Key Set) used for token signature validation. Default is 3600 seconds (1 hour)
AZURE_AD_JWK_CACHE_TIMEOUT = 3600  # 1 hora

# Time in seconds to cache the additional user information retrieved from the external service. Default is 3600 seconds (1 hour).
AZURE_AD_AUX_USERINFO_CACHE_TIMEOUT = 3600  # 1 hora

# Mapping between fields returned by the additional service and request attributes
# Format: {"service_field": "request_attribute_name"}
AZURE_AD_AUX_USERINFO_MAPPING = {
    "department": "azure_department",
    "department_number": "azure_department_number",
    "company": "azure_company",
    "employee_number": "azure_employee_role",
}


```

### 3. Usage in views

To enable token validation in a DRF view or viewset, set the attribute `azure_authentication = True` in the view class:

```python
from rest_framework import viewsets, routers
from rest_framework.response import Response


class DummyViewSet(viewsets.ViewSet):
    azure_authentication = True

    def list(self, request):
        return Response(
            {
                "user": getattr(request, "azure_username", None),
                "roles": getattr(request, "azure_roles", []),
                "email": getattr(request, "azure_email", None),
            }
        )
```

---

## Application Authentication in Azure AD

The package provides a utility function to authenticate applications in Azure AD using the `client_credentials` flow. This function is useful for scenarios where an application needs to communicate with another protected application.

### Function: `generate_app_azure_token`

The `generate_app_azure_token` function returns a valid access token for the application. The token is cached and automatically renewed upon expiration.

#### Example usage:

```python
from azvalidator.utils import generate_app_azure_token

# Get the access token
access_token = generate_app_azure_token()
print(f"Access token: {access_token}")
```
#### Cache Configuration (New)
To ensure proper caching of Azure AD tokens used by `generate_app_azure_token`, you must configure Django’s cache settings in your `settings.py`. For local development or testing, you can use the simple in-memory cache backend:
Ensure the following variables are configured correctly for the function to work:
```python 
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}
```
#### Configuration for application authentication (client credentials)
```python
# Azure AD authentication endpoint URL
AZURE_AD_URL = "https://login.microsoftonline.com"

# Azure AD Tenant ID
AZURE_AD_TENANT_ID = "<tenant_id>"

# Grant type (must be "client_credentials")
AZURE_AD_APP_GRANT_TYPE = "client_credentials"

# Client ID registered in Azure AD
AZURE_AD_APP_CLIENT_ID = "<client_id>"

# Client secret registered in Azure AD
AZURE_AD_APP_CLIENT_SECRET = "<client_secret>"

# Required access scope
AZURE_AD_APP_SCOPE = "https://graph.microsoft.com/.default"
```

---

## External Service for Additional User Information

### Purpose

The middleware can enrich the `request` object with extra data fetched from an external service, in addition to the basic Azure AD token data.

### How it works

- After validating the token, the middleware makes an HTTP GET request to:

  ```
  {AZURE_AD_AUX_USERINFO_SERVICE_URL}/{username}/
  ```

- If configured, it sends a Bearer token via the `Authorization` header for authentication.

- The external service must return a JSON response with the additional user data.

### External service specifications

- **Endpoint:** REST, accepting GET requests at the URL `/username/`
- **Authentication:** Optional via Bearer Token
- **Response:** JSON with fields containing user data (example below)

Example JSON response:

```json
{
  "department": "Information Technology",
  "department_number": "123",
  "company": "MyCompany",
  "employee_number": "456789",
  "other_field": "value"
}
```

### Mapping data to the `request`

The dictionary `AZURE_AD_AUX_USERINFO_MAPPING` defines which fields from the JSON response will be added to the `request` object and under which names, for example:

```python
AZURE_AD_AUX_USERINFO_MAPPING = {
    "department": "azure_department",
    "department_number": "azure_department_number",
    "company": "azure_company",
    "employee_number": "azure_employee_role",
}
```

### Timeout and Resilience

- Request timeout is configurable via `AZURE_AD_AUX_USERINFO_SERVICE_TIMEOUT` (default: 10 seconds).
- If the service is unavailable or an error occurs, the middleware logs the failure and continues the request without additional data.

---


## Tests

The package's test suite covers the main middleware scenarios to ensure robustness:

- Validation of a valid token with the `preferred_username` claim.
- Rejection of a token without the `preferred_username` claim (returns HTTP 401).
- Rejection of a token with an invalid signature.
- Rejection of an expired token.
- Handling of Client Credentials tokens (app-to-app).
- Enrichment of the request with additional information via an external service.
- Appropriate responses with status 401 or 500 based on detected errors.

### Basic test example:

```bash
cd tests && pip install -r requirements.txt && python manage.py test
```
