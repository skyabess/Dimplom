from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'contracts'

router = DefaultRouter()
router.register(r'', views.ContractViewSet, basename='contracts')

urlpatterns = [
    path(
        'tasks/',
        views.ContractTaskViewSet.as_view({'get': 'list', 'post': 'create'}),
        name='contract-tasks',
    ),
    path(
        'tasks/<uuid:pk>/',
        views.ContractTaskViewSet.as_view({
            'get': 'retrieve',
            'patch': 'partial_update',
            'delete': 'destroy',
        }),
        name='contract-task-detail',
    ),
    path(
        '<uuid:contract_pk>/documents/',
        views.ContractDocumentViewSet.as_view({'get': 'list', 'post': 'create'}),
        name='contract-documents',
    ),
    path(
        '<uuid:contract_pk>/documents/<uuid:pk>/',
        views.ContractDocumentViewSet.as_view({
            'get': 'retrieve',
            'patch': 'partial_update',
            'delete': 'destroy',
        }),
        name='contract-document-detail',
    ),
    # Contract endpoints
    path('', include(router.urls)),
]
