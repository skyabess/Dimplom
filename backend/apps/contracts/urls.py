from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'contracts'

router = DefaultRouter()
router.register(r'', views.ContractViewSet, basename='contracts')

urlpatterns = [
    # Contract endpoints
    path('', include(router.urls)),
]
