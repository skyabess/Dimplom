from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'contracts'

router = DefaultRouter()
router.register(r'', views.ContractViewSet, basename='contracts')

urlpatterns = [
    # Contract endpoints
    path('', include(router.urls)),
    
    # Contract-specific actions
    path('<uuid:pk>/sign/', views.ContractSignView.as_view(), name='contract-sign'),
    path('<uuid:pk>/generate-document/', views.ContractGenerateDocumentView.as_view(), name='contract-generate-document'),
    path('<uuid:pk>/send-for-signature/', views.ContractSendForSignatureView.as_view(), name='contract-send-for-signature'),
    path('<uuid:pk>/verify-signature/', views.ContractVerifySignatureView.as_view(), name='contract-verify-signature'),
    path('<uuid:pk>/cancel/', views.ContractCancelView.as_view(), name='contract-cancel'),
    path('<uuid:pk>/archive/', views.ContractArchiveView.as_view(), name='contract-archive'),
    
    # Contract statistics
    path('statistics/', views.ContractStatisticsView.as_view(), name='contract-statistics'),
    
    # Contract templates
    path('templates/', views.ContractTemplateListView.as_view(), name='contract-templates'),
    path('templates/<int:pk>/', views.ContractTemplateDetailView.as_view(), name='contract-template-detail'),
]