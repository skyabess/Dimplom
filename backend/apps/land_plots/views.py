from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.gis.geos import GEOSGeometry, Point
from django.contrib.gis.measure import Distance
from django.contrib.gis.db.models.functions import Distance as GISDistance
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import logging

from .models import (
    LandCategory, LandPurpose, Region, District, Settlement, LandPlot,
    LandPlotOwner, LandPlotDocument, LandPlotEncumbrance, LandPlotValuation
)
from .serializers import (
    LandCategorySerializer, LandPurposeSerializer, RegionSerializer,
    DistrictSerializer, SettlementSerializer, LandPlotSerializer,
    LandPlotCreateSerializer, LandPlotUpdateSerializer, LandPlotListSerializer,
    LandPlotSearchSerializer, LandPlotOwnerSerializer, LandPlotDocumentSerializer,
    LandPlotEncumbranceSerializer, LandPlotValuationSerializer
)
from users.permissions import (
    CanManageLandPlots, CanViewLandPlots, IsOwnerOrReadOnly, IsAdminUser
)

logger = logging.getLogger(__name__)


class LandCategoryListView(generics.ListCreateAPIView):
    """List and create land categories."""
    queryset = LandCategory.objects.filter(is_active=True)
    serializer_class = LandCategorySerializer
    permission_classes = [permissions.IsAuthenticated, CanViewLandPlots]
    
    @swagger_auto_schema(
        operation_description="List all active land categories",
        responses={200: LandCategorySerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Create new land category",
        responses={201: LandCategorySerializer()}
    )
    def post(self, request, *args, **kwargs):
        if not request.user.roles.filter(role__in=['system_admin', 'company_admin']).exists():
            return Response(
                {'error': 'Insufficient permissions'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        return super().post(request, *args, **kwargs)


class LandPurposeListView(generics.ListCreateAPIView):
    """List and create land purposes."""
    queryset = LandPurpose.objects.filter(is_active=True)
    serializer_class = LandPurposeSerializer
    permission_classes = [permissions.IsAuthenticated, CanViewLandPlots]
    
    @swagger_auto_schema(
        operation_description="List all active land purposes",
        responses={200: LandPurposeSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Create new land purpose",
        responses={201: LandPurposeSerializer()}
    )
    def post(self, request, *args, **kwargs):
        if not request.user.roles.filter(role__in=['system_admin', 'company_admin']).exists():
            return Response(
                {'error': 'Insufficient permissions'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        return super().post(request, *args, **kwargs)


class RegionListView(generics.ListCreateAPIView):
    """List and create regions."""
    queryset = Region.objects.filter(is_active=True)
    serializer_class = RegionSerializer
    permission_classes = [permissions.IsAuthenticated, CanViewLandPlots]
    
    @swagger_auto_schema(
        operation_description="List all active regions",
        responses={200: RegionSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class DistrictListView(generics.ListCreateAPIView):
    """List and create districts."""
    serializer_class = DistrictSerializer
    permission_classes = [permissions.IsAuthenticated, CanViewLandPlots]
    
    def get_queryset(self):
        region_id = self.request.query_params.get('region_id')
        if region_id:
            return District.objects.filter(region_id=region_id, is_active=True)
        return District.objects.filter(is_active=True)
    
    @swagger_auto_schema(
        operation_description="List districts by region",
        responses={200: DistrictSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class SettlementListView(generics.ListCreateAPIView):
    """List and create settlements."""
    serializer_class = SettlementSerializer
    permission_classes = [permissions.IsAuthenticated, CanViewLandPlots]
    
    def get_queryset(self):
        district_id = self.request.query_params.get('district_id')
        if district_id:
            return Settlement.objects.filter(district_id=district_id, is_active=True)
        return Settlement.objects.filter(is_active=True)
    
    @swagger_auto_schema(
        operation_description="List settlements by district",
        responses={200: SettlementSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class LandPlotPagination(PageNumberPagination):
    """Custom pagination for land plots."""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class LandPlotListView(generics.ListCreateAPIView):
    """List and create land plots."""
    serializer_class = LandPlotListSerializer
    permission_classes = [permissions.IsAuthenticated, CanViewLandPlots]
    pagination_class = LandPlotPagination
    filter_backends = [DjangoFilterBackend]
    filterset_fields = [
        'region', 'district', 'settlement', 'category', 'purpose',
        'ownership_type', 'is_verified', 'is_active'
    ]
    
    def get_queryset(self):
        queryset = LandPlot.objects.select_related(
            'region', 'district', 'settlement', 'category', 'purpose', 'created_by'
        ).prefetch_related('owners', 'documents', 'encumbrances', 'valuations')
        
        # Search by cadastral number or address
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                models.Q(cadastral_number__icontains=search) |
                models.Q(address__icontains=search)
            )
        
        # Filter by area range
        area_min = self.request.query_params.get('area_min')
        area_max = self.request.query_params.get('area_max')
        if area_min:
            queryset = queryset.filter(area__gte=area_min)
        if area_max:
            queryset = queryset.filter(area__lte=area_max)
        
        # Geospatial filters
        within_distance = self.request.query_params.get('within_distance')
        center_point = self.request.query_params.get('center_point')
        
        if center_point and within_distance:
            try:
                point = GEOSGeometry(center_point)
                distance = Distance(km=float(within_distance))
                queryset = queryset.filter(
                    centroid__distance_lte=(point, distance)
                ).annotate(
                    distance=GISDistance('centroid', point)
                ).order_by('distance')
            except Exception as e:
                logger.error(f"Geospatial filter error: {str(e)}")
        
        return queryset
    
    @swagger_auto_schema(
        operation_description="List land plots with filters",
        responses={200: LandPlotListSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Create new land plot",
        responses={201: LandPlotSerializer()}
    )
    def post(self, request, *args, **kwargs):
        if not CanManageLandPlots().has_permission(request, self):
            return Response(
                {'error': 'Insufficient permissions'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = LandPlotCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            land_plot = serializer.save(created_by=request.user)
            
            # Log activity
            from users.models import UserActivityLog
            UserActivityLog.objects.create(
                user=request.user,
                action='create_land_plot',
                object_type='LandPlot',
                object_id=str(land_plot.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f'Land plot {land_plot.cadastral_number} created'
            )
            
            return Response(
                LandPlotSerializer(land_plot).data,
                status=status.HTTP_201_CREATED
            )


class LandPlotDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Retrieve, update and delete land plot."""
    serializer_class = LandPlotSerializer
    permission_classes = [permissions.IsAuthenticated, CanViewLandPlots]
    
    def get_queryset(self):
        return LandPlot.objects.select_related(
            'region', 'district', 'settlement', 'category', 'purpose', 'created_by'
        ).prefetch_related('owners', 'documents', 'encumbrances', 'valuations')
    
    @swagger_auto_schema(
        operation_description="Get land plot details",
        responses={200: LandPlotSerializer()}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Update land plot",
        responses={200: LandPlotSerializer()}
    )
    def patch(self, request, *args, **kwargs):
        if not CanManageLandPlots().has_permission(request, self):
            return Response(
                {'error': 'Insufficient permissions'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        land_plot = self.get_object()
        serializer = LandPlotUpdateSerializer(
            land_plot, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            updated_land_plot = serializer.save()
            
            # Log activity
            from users.models import UserActivityLog
            UserActivityLog.objects.create(
                user=request.user,
                action='edit_land_plot',
                object_type='LandPlot',
                object_id=str(land_plot.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f'Land plot {land_plot.cadastral_number} updated'
            )
            
            return Response(LandPlotSerializer(updated_land_plot).data)
    
    @swagger_auto_schema(
        operation_description="Delete land plot",
        responses={204: "No Content"}
    )
    def delete(self, request, *args, **kwargs):
        if not CanManageLandPlots().has_permission(request, self):
            return Response(
                {'error': 'Insufficient permissions'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        land_plot = self.get_object()
        
        with transaction.atomic():
            # Log activity
            from users.models import UserActivityLog
            UserActivityLog.objects.create(
                user=request.user,
                action='delete_land_plot',
                object_type='LandPlot',
                object_id=str(land_plot.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f'Land plot {land_plot.cadastral_number} deleted'
            )
            
            return super().delete(request, *args, **kwargs)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, CanViewLandPlots])
def land_plot_search(request):
    """Advanced land plot search."""
    serializer = LandPlotSearchSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    queryset = LandPlot.objects.select_related(
        'region', 'district', 'settlement', 'category', 'purpose', 'created_by'
    )
    
    # Apply filters
    search_data = serializer.validated_data
    
    if search_data.get('query'):
        queryset = queryset.filter(
            models.Q(cadastral_number__icontains=search_data['query']) |
            models.Q(address__icontains=search_data['query'])
        )
    
    if search_data.get('cadastral_number'):
        queryset = queryset.filter(
            cadastral_number__icontains=search_data['cadastral_number']
        )
    
    # Apply specific filters
    filter_fields = [
        'region', 'district', 'settlement', 'category', 'purpose',
        'ownership_type', 'is_verified', 'is_active'
    ]
    
    for field in filter_fields:
        if search_data.get(field) is not None:
            queryset = queryset.filter(**{field: search_data[field]})
    
    # Area range filter
    if search_data.get('area_min'):
        queryset = queryset.filter(area__gte=search_data['area_min'])
    if search_data.get('area_max'):
        queryset = queryset.filter(area__lte=search_data['area_max'])
    
    # Geospatial search
    if search_data.get('within_geometry'):
        try:
            geometry = GEOSGeometry(str(search_data['within_geometry']))
            queryset = queryset.filter(geometry__within=geometry)
        except Exception as e:
            logger.error(f"Geospatial search error: {str(e)}")
    
    if search_data.get('center_point') and search_data.get('within_distance'):
        try:
            point = GEOSGeometry(str(search_data['center_point']))
            distance = Distance(km=search_data['within_distance'])
            queryset = queryset.filter(
                centroid__distance_lte=(point, distance)
            ).annotate(
                distance=GISDistance('centroid', point)
            ).order_by('distance')
        except Exception as e:
            logger.error(f"Geospatial search error: {str(e)}")
    
    # Ordering
    ordering = search_data.get('ordering', '-created_at')
    queryset = queryset.order_by(ordering)
    
    # Pagination
    page = search_data.get('page', 1)
    page_size = search_data.get('page_size', 20)
    
    start = (page - 1) * page_size
    end = start + page_size
    
    total_count = queryset.count()
    items = queryset[start:end]
    
    return Response({
        'count': total_count,
        'page': page,
        'page_size': page_size,
        'results': LandPlotListSerializer(items, many=True).data
    })


class LandPlotOwnerListView(generics.ListCreateAPIView):
    """List and create land plot owners."""
    serializer_class = LandPlotOwnerSerializer
    permission_classes = [permissions.IsAuthenticated, CanManageLandPlots]
    
    def get_queryset(self):
        land_plot_id = self.kwargs.get('land_plot_id')
        return LandPlotOwner.objects.filter(land_plot_id=land_plot_id).select_related('owner')
    
    @swagger_auto_schema(
        operation_description="List land plot owners",
        responses={200: LandPlotOwnerSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Add owner to land plot",
        responses={201: LandPlotOwnerSerializer()}
    )
    def post(self, request, *args, **kwargs):
        land_plot_id = self.kwargs.get('land_plot_id')
        try:
            land_plot = LandPlot.objects.get(id=land_plot_id)
        except LandPlot.DoesNotExist:
            return Response(
                {'error': 'Land plot not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            owner = serializer.save(land_plot=land_plot)
            
            # Log activity
            from users.models import UserActivityLog
            UserActivityLog.objects.create(
                user=request.user,
                action='add_land_plot_owner',
                object_type='LandPlotOwner',
                object_id=str(owner.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f'Owner added to land plot {land_plot.cadastral_number}'
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)


class LandPlotDocumentListView(generics.ListCreateAPIView):
    """List and create land plot documents."""
    serializer_class = LandPlotDocumentSerializer
    permission_classes = [permissions.IsAuthenticated, CanManageLandPlots]
    
    def get_queryset(self):
        land_plot_id = self.kwargs.get('land_plot_id')
        return LandPlotDocument.objects.filter(land_plot_id=land_plot_id).select_related('uploaded_by')
    
    @swagger_auto_schema(
        operation_description="List land plot documents",
        responses={200: LandPlotDocumentSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
    
    @swagger_auto_schema(
        operation_description="Upload document to land plot",
        responses={201: LandPlotDocumentSerializer()}
    )
    def post(self, request, *args, **kwargs):
        land_plot_id = self.kwargs.get('land_plot_id')
        try:
            land_plot = LandPlot.objects.get(id=land_plot_id)
        except LandPlot.DoesNotExist:
            return Response(
                {'error': 'Land plot not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            document = serializer.save(
                land_plot=land_plot,
                uploaded_by=request.user,
                file_size=request.FILES['file'].size,
                file_name=request.FILES['file'].name
            )
            
            # Calculate file hash
            import hashlib
            file_hash = hashlib.sha256()
            for chunk in document.file.chunks():
                file_hash.update(chunk)
            document.file_hash = file_hash.hexdigest()
            document.save()
            
            # Log activity
            from users.models import UserActivityLog
            UserActivityLog.objects.create(
                user=request.user,
                action='upload_land_plot_document',
                object_type='LandPlotDocument',
                object_id=str(document.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description=f'Document uploaded to land plot {land_plot.cadastral_number}'
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)


def get_client_ip(request):
    """Get client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip