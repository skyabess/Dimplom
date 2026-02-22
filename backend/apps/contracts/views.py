"""
Views for contracts app
"""
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q, Count, Avg, Sum
from django.utils import timezone
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from apps.core.permissions import IsOwnerOrReadOnly, IsAuthenticated
from apps.core.pagination import StandardResultsSetPagination
from apps.contracts.models import (
    Contract, ContractDocument, ContractSignature, 
    ContractStage, ContractTemplate, ContractComment
)
from apps.contracts.serializers import (
    ContractSerializer, ContractDetailSerializer, ContractCreateSerializer,
    ContractDocumentSerializer, ContractSignatureSerializer,
    ContractStageSerializer, ContractTemplateSerializer,
    ContractCommentSerializer
)
from apps.contracts.filters import ContractFilter
from apps.contracts.services import ContractService
from apps.contracts.permissions import CanSignContract, CanViewContract


class ContractViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing contracts
    """
    serializer_class = ContractSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_class = ContractFilter
    pagination_class = StandardResultsSetPagination
    lookup_field = 'id'
    
    def get_queryset(self):
        """
        Get contracts based on user role and permissions
        """
        user = self.request.user
        queryset = Contract.objects.select_related(
            'seller', 'buyer', 'land_plot'
        ).prefetch_related(
            'documents', 'signatures', 'stages'
        )
        
        # Filter based on user role
        if user.role == 'seller':
            queryset = queryset.filter(seller=user)
        elif user.role == 'buyer':
            queryset = queryset.filter(buyer=user)
        elif user.role == 'agent':
            # Agents can see contracts they represent
            queryset = queryset.filter(
                Q(seller=user) | Q(buyer=user)
            )
        elif user.role == 'notary':
            # Notaries can see all contracts in their region
            queryset = queryset.filter(
                land_plot__region=user.region
            )
        elif user.role == 'admin':
            # Admins can see all contracts
            pass
        else:
            queryset = queryset.none()
        
        return queryset
    
    def get_serializer_class(self):
        """
        Return appropriate serializer based on action
        """
        if self.action == 'create':
            return ContractCreateSerializer
        elif self.action == 'retrieve':
            return ContractDetailSerializer
        return self.serializer_class
    
    def perform_create(self, serializer):
        """
        Create contract with proper permissions and logging
        """
        user = self.request.user
        contract_service = ContractService()
        
        # Create contract through service layer
        contract = contract_service.create_contract(
            user=user,
            validated_data=serializer.validated_data
        )
        
        return contract
    
    @extend_schema(
        summary="Подписать договор",
        description="Подписание договора с использованием электронной подписи",
        parameters=[
            OpenApiParameter(
                name="signature_data",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Данные электронной подписи"
            )
        ]
    )
    @action(detail=True, methods=['post'], permission_classes=[CanSignContract])
    def sign(self, request, pk=None):
        """
        Sign contract with electronic signature
        """
        contract = self.get_object()
        contract_service = ContractService()
        
        try:
            signature = contract_service.sign_contract(
                contract=contract,
                user=request.user,
                signature_data=request.data.get('signature_data'),
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )
            
            return Response({
                'message': 'Договор успешно подписан',
                'signature_id': signature.id
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e),
                'message': 'Ошибка при подписании договора'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Получить историю договора",
        description="Получить полную историю изменений договора"
    )
    @action(detail=True, methods=['get'])
    def history(self, request, pk=None):
        """
        Get contract history and changes
        """
        contract = self.get_object()
        contract_service = ContractService()
        
        history = contract_service.get_contract_history(contract)
        
        return Response({
            'contract_id': str(contract.id),
            'history': history
        })
    
    @extend_schema(
        summary="Сгенерировать документ",
        description="Генерация PDF документа на основе шаблона"
    )
    @action(detail=True, methods=['post'])
    def generate_document(self, request, pk=None):
        """
        Generate contract document
        """
        contract = self.get_object()
        template_id = request.data.get('template_id')
        
        contract_service = ContractService()
        
        try:
            document = contract_service.generate_document(
                contract=contract,
                template_id=template_id,
                user=request.user
            )
            
            return Response({
                'message': 'Документ успешно сгенерирован',
                'document_id': document.id,
                'download_url': document.file.url
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'error': str(e),
                'message': 'Ошибка при генерации документа'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @extend_schema(
        summary="Статистика по договорам",
        description="Получить статистику по договорам пользователя"
    )
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """
        Get contract statistics for current user
        """
        user = request.user
        queryset = self.get_queryset()
        
        # Basic statistics
        stats = {
            'total_contracts': queryset.count(),
            'active_contracts': queryset.filter(status='active').count(),
            'pending_contracts': queryset.filter(
                status__in=['pending_approval', 'pending_signature']
            ).count(),
            'completed_contracts': queryset.filter(status='completed').count(),
        }
        
        # Financial statistics
        financial_stats = queryset.aggregate(
            total_value=Sum('price'),
            avg_value=Avg('price'),
            total_with_fees=Sum('price') + Sum('additional_fees')
        )
        
        stats.update({
            'total_value': financial_stats['total_value'] or 0,
            'average_value': financial_stats['avg_value'] or 0,
            'total_with_fees': financial_stats['total_with_fees'] or 0,
        })
        
        # Monthly statistics
        current_month = timezone.now().replace(day=1)
        monthly_stats = queryset.filter(
            created_at__gte=current_month
        ).aggregate(
            monthly_contracts=Count('id'),
            monthly_value=Sum('price')
        )
        
        stats.update({
            'monthly_contracts': monthly_stats['monthly_contracts'] or 0,
            'monthly_value': monthly_stats['monthly_value'] or 0,
        })
        
        return Response(stats)


class ContractDocumentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing contract documents
    """
    serializer_class = ContractDocumentSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        """
        Get documents for specific contract
        """
        contract_id = self.kwargs.get('contract_pk')
        if contract_id:
            return ContractDocument.objects.filter(
                contract_id=contract_id
            ).select_related('contract')
        return ContractDocument.objects.none()
    
    def perform_create(self, serializer):
        """
        Create document with file validation
        """
        contract_id = self.kwargs.get('contract_pk')
        user = self.request.user
        
        # Validate file
        uploaded_file = serializer.validated_data.get('file')
        if uploaded_file:
            # File size validation
            max_size = 100 * 1024 * 1024  # 100MB
            if uploaded_file.size > max_size:
                raise ValidationError({
                    'file': 'Размер файла превышает 100MB'
                })
            
            # File type validation
            allowed_types = [
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            ]
            
            if uploaded_file.content_type not in allowed_types:
                raise ValidationError({
                    'file': 'Неподдерживаемый тип файла'
                })
        
        return serializer.save(
            contract_id=contract_id,
            uploaded_by=user
        )


class ContractSignatureViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing contract signatures
    """
    serializer_class = ContractSignatureSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post']
    
    def get_queryset(self):
        """
        Get signatures for specific contract
        """
        contract_id = self.kwargs.get('contract_pk')
        if contract_id:
            return ContractSignature.objects.filter(
                contract_id=contract_id
            ).select_related('signer', 'contract')
        return ContractSignature.objects.none()
    
    def create(self, request, *args, **kwargs):
        """
        Create signature with validation
        """
        contract_id = kwargs.get('contract_pk')
        user = request.user
        
        # Check if user can sign this contract
        try:
            contract = Contract.objects.get(id=contract_id)
        except Contract.DoesNotExist:
            return Response({
                'error': 'Договор не найден'
            }, status=status.HTTP_404_NOT_FOUND)
        
        if not self._can_sign_contract(user, contract):
            return Response({
                'error': 'У вас нет прав для подписания этого договора'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Validate signature data
        signature_data = request.data.get('signature_data')
        if not signature_data:
            return Response({
                'error': 'Отсутствуют данные подписи'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create signature through service
        contract_service = ContractService()
        
        try:
            signature = contract_service.create_signature(
                contract=contract,
                user=user,
                signature_data=signature_data,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )
            
            return Response({
                'message': 'Подпись успешно создана',
                'signature_id': signature.id
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'error': str(e),
                'message': 'Ошибка при создании подписи'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def _can_sign_contract(self, user, contract):
        """
        Check if user can sign the contract
        """
        # Seller can sign
        if user == contract.seller and contract.status == 'pending_signature':
            return True
        
        # Buyer can sign
        if user == contract.buyer and contract.status == 'pending_signature':
            return True
        
        # Notary can sign
        if user.role == 'notary' and contract.status in ['signed', 'active']:
            return True
        
        return False


class ContractStageViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing contract stages
    """
    serializer_class = ContractStageSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """
        Get stages for specific contract
        """
        contract_id = self.kwargs.get('contract_pk')
        if contract_id:
            return ContractStage.objects.filter(
                contract_id=contract_id
            ).order_by('order')
        return ContractStage.objects.none()
    
    @action(detail=True, methods=['post'])
    def complete_stage(self, request, pk=None):
        """
        Mark stage as completed
        """
        stage = self.get_object()
        user = request.user
        
        contract_service = ContractService()
        
        try:
            updated_stage = contract_service.complete_stage(
                stage=stage,
                user=user
            )
            
            return Response({
                'message': 'Этап успешно завершен',
                'stage': ContractStageSerializer(updated_stage).data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e),
                'message': 'Ошибка при завершении этапа'
            }, status=status.HTTP_400_BAD_REQUEST)


class ContractTemplateViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing contract templates
    """
    serializer_class = ContractTemplateSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        """
        Get active templates
        """
        user = self.request.user
        
        if user.role == 'admin':
            return ContractTemplate.objects.all()
        else:
            return ContractTemplate.objects.filter(
                is_active=True
            )
    
    @action(detail=True, methods=['post'])
    def preview(self, request, pk=None):
        """
        Preview template with sample data
        """
        template = self.get_object()
        sample_data = request.data.get('sample_data', {})
        
        contract_service = ContractService()
        
        try:
            preview = contract_service.preview_template(
                template=template,
                data=sample_data
            )
            
            return Response({
                'preview': preview
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': str(e),
                'message': 'Ошибка при генерации предпросмотра'
            }, status=status.HTTP_400_BAD_REQUEST)


class ContractCommentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing contract comments
    """
    serializer_class = ContractCommentSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        """
        Get comments for specific contract
        """
        contract_id = self.kwargs.get('contract_pk')
        user = self.request.user
        
        if contract_id:
            queryset = ContractComment.objects.filter(
                contract_id=contract_id
            ).select_related('author', 'parent')
            
            # Filter internal comments for non-admin users
            if user.role != 'admin':
                queryset = queryset.filter(is_internal=False)
            
            return queryset
        return ContractComment.objects.none()
    
    def perform_create(self, serializer):
        """
        Create comment with proper permissions
        """
        contract_id = self.kwargs.get('contract_pk')
        user = self.request.user
        
        return serializer.save(
            contract_id=contract_id,
            author=user
        )