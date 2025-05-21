from django.urls import path, include
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


router = routers.DefaultRouter()
router.register(r'dummy', DummyViewSet, basename='dummy')

urlpatterns = [
    path('', include(router.urls)),
]
