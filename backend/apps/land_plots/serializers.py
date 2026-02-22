from rest_framework import serializers
from django.contrib.gis.geos import Polygon, Point
from django.contrib.gis.measure import Distance
from .models import (
    LandCategory, LandPurpose, Region, District, Settlement, LandPlot,
    LandPlotOwner, LandPlotDocument, LandPlotEncumbrance, LandPlotValuation
)


class LandCategorySerializer(serializers.ModelSerializer):
    """Serializer for land categories."""
    
    class Meta:
        model = LandCategory
        fields = ['id', 'name', 'code', 'description', 'is_active']
        read_only_fields = ['id']


class LandPurposeSerializer(serializers.ModelSerializer):
    """Serializer for land purposes."""
    
    class Meta:
        model = LandPurpose
        fields = ['id', 'name', 'code', 'description', 'is_active']
        read_only_fields = ['id']


class RegionSerializer(serializers.ModelSerializer):
    """Serializer for regions."""
    
    class Meta:
        model = Region
        fields = ['id', 'name', 'code', 'okato_code', 'is_active']
        read_only_fields = ['id']


class DistrictSerializer(serializers.ModelSerializer):
    """Serializer for districts."""
    region_name = serializers.CharField(source='region.name', read_only=True)
    
    class Meta:
        model = District
        fields = ['id', 'region', 'region_name', 'name', 'code', 'is_active']
        read_only_fields = ['id']


class SettlementSerializer(serializers.ModelSerializer):
    """Serializer for settlements."""
    district_name = serializers.CharField(source='district.name', read_only=True)
    region_name = serializers.CharField(source='district.region.name', read_only=True)
    
    class Meta:
        model = Settlement
        fields = ['id', 'district', 'district_name', 'region_name', 'name', 'type', 'is_active']
        read_only_fields = ['id']


class LandPlotOwnerSerializer(serializers.ModelSerializer):
    """Serializer for land plot owners."""
    owner_name = serializers.CharField(source='owner.full_name', read_only=True)
    ownership_type_display = serializers.CharField(source='get_ownership_type_display', read_only=True)
    
    class Meta:
        model = LandPlotOwner
        fields = [
            'id', 'owner', 'owner_name', 'ownership_share', 'ownership_type',
            'ownership_type_display', 'is_primary_owner', 'ownership_document_number',
            'ownership_document_date', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class LandPlotDocumentSerializer(serializers.ModelSerializer):
    """Serializer for land plot documents."""
    uploaded_by_name = serializers.CharField(source='uploaded_by.full_name', read_only=True)
    document_type_display = serializers.CharField(source='get_document_type_display', read_only=True)
    file_size_display = serializers.SerializerMethodField()
    
    class Meta:
        model = LandPlotDocument
        fields = [
            'id', 'document_type', 'document_type_display', 'document_number',
            'document_date', 'issued_by', 'file', 'file_name', 'file_size',
            'file_size_display', 'file_hash', 'description', 'is_verified',
            'uploaded_by', 'uploaded_by_name', 'uploaded_at'
        ]
        read_only_fields = ['id', 'file_size', 'file_hash', 'uploaded_at']
    
    def get_file_size_display(self, obj):
        """Return human-readable file size."""
        size = obj.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"


class LandPlotEncumbranceSerializer(serializers.ModelSerializer):
    """Serializer for land plot encumbrances."""
    created_by_name = serializers.CharField(source='created_by.full_name', read_only=True)
    encumbrance_type_display = serializers.CharField(source='get_encumbrance_type_display', read_only=True)
    
    class Meta:
        model = LandPlotEncumbrance
        fields = [
            'id', 'encumbrance_type', 'encumbrance_type_display', 'description',
            'registration_number', 'registration_date', 'start_date', 'end_date',
            'is_active', 'beneficiary', 'created_by', 'created_by_name',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class LandPlotValuationSerializer(serializers.ModelSerializer):
    """Serializer for land plot valuations."""
    created_by_name = serializers.CharField(source='created_by.full_name', read_only=True)
    valuation_type_display = serializers.CharField(source='get_valuation_type_display', read_only=True)
    
    class Meta:
        model = LandPlotValuation
        fields = [
            'id', 'valuation_type', 'valuation_type_display', 'value',
            'valuation_date', 'valuator', 'valuation_report_number',
            'notes', 'created_by', 'created_by_name', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class LandPlotSerializer(serializers.ModelSerializer):
    """Serializer for land plots."""
    created_by_name = serializers.CharField(source='created_by.full_name', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    purpose_name = serializers.CharField(source='purpose.name', read_only=True)
    region_name = serializers.CharField(source='region.name', read_only=True)
    district_name = serializers.CharField(source='district.name', read_only=True)
    settlement_name = serializers.CharField(source='settlement.name', read_only=True)
    ownership_type_display = serializers.CharField(source='get_ownership_type_display', read_only=True)
    area_hectares = serializers.ReadOnlyField()
    full_address = serializers.ReadOnlyField()
    
    # Nested serializers
    owners = LandPlotOwnerSerializer(many=True, read_only=True)
    documents = LandPlotDocumentSerializer(many=True, read_only=True)
    encumbrances = LandPlotEncumbranceSerializer(many=True, read_only=True)
    valuations = LandPlotValuationSerializer(many=True, read_only=True)
    
    # Geometry fields
    geometry_coordinates = serializers.SerializerMethodField()
    centroid_coordinates = serializers.SerializerMethodField()
    
    class Meta:
        model = LandPlot
        fields = [
            'id', 'cadastral_number', 'region', 'region_name', 'district',
            'district_name', 'settlement', 'settlement_name', 'address',
            'area', 'area_hectares', 'category', 'category_name', 'purpose',
            'purpose_name', 'geometry', 'geometry_coordinates', 'centroid',
            'centroid_coordinates', 'ownership_type', 'ownership_type_display',
            'is_verified', 'verification_date', 'is_active', 'notes',
            'created_by', 'created_by_name', 'created_at', 'updated_at',
            'full_address', 'owners', 'documents', 'encumbrances', 'valuations'
        ]
        read_only_fields = [
            'id', 'is_verified', 'verification_date', 'created_at', 'updated_at'
        ]
    
    def get_geometry_coordinates(self, obj):
        """Return geometry coordinates in GeoJSON format."""
        if obj.geometry:
            return obj.geometry.geojson
        return None
    
    def get_centroid_coordinates(self, obj):
        """Return centroid coordinates."""
        if obj.centroid:
            return {
                'type': 'Point',
                'coordinates': [obj.centroid.x, obj.centroid.y]
            }
        return None
    
    def validate_geometry(self, value):
        """Validate geometry field."""
        if not isinstance(value, (Polygon, str)):
            raise serializers.ValidationError("Geometry must be a Polygon or GeoJSON string")
        
        if isinstance(value, str):
            try:
                # Try to parse GeoJSON string
                from django.contrib.gis.geos import GEOSGeometry
                value = GEOSGeometry(value)
            except Exception:
                raise serializers.ValidationError("Invalid GeoJSON format")
        
        if value.geom_type != 'Polygon':
            raise serializers.ValidationError("Geometry must be a Polygon")
        
        return value
    
    def validate_cadastral_number(self, value):
        """Validate cadastral number format."""
        import re
        pattern = r'^\d{2}:\d{2}:\d{6,7}:\d{1,6}$'
        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Invalid cadastral number format. Expected format: XX:XX:XXXXXXX:XXXX"
            )
        return value


class LandPlotCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating land plots."""
    geometry_geojson = serializers.JSONField(write_only=True, required=False)
    
    class Meta:
        model = LandPlot
        fields = [
            'cadastral_number', 'region', 'district', 'settlement', 'address',
            'area', 'category', 'purpose', 'geometry_geojson', 'ownership_type',
            'notes'
        ]
    
    def create(self, validated_data):
        """Create land plot with geometry from GeoJSON."""
        geometry_geojson = validated_data.pop('geometry_geojson', None)
        
        if geometry_geojson:
            from django.contrib.gis.geos import GEOSGeometry
            geometry = GEOSGeometry(str(geometry_geojson))
            validated_data['geometry'] = geometry
        
        return super().create(validated_data)


class LandPlotUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating land plots."""
    geometry_geojson = serializers.JSONField(write_only=True, required=False)
    
    class Meta:
        model = LandPlot
        fields = [
            'region', 'district', 'settlement', 'address', 'area', 'category',
            'purpose', 'geometry_geojson', 'ownership_type', 'notes', 'is_active'
        ]
    
    def update(self, instance, validated_data):
        """Update land plot with geometry from GeoJSON."""
        geometry_geojson = validated_data.pop('geometry_geojson', None)
        
        if geometry_geojson:
            from django.contrib.gis.geos import GEOSGeometry
            geometry = GEOSGeometry(str(geometry_geojson))
            validated_data['geometry'] = geometry
        
        return super().update(instance, validated_data)


class LandPlotListSerializer(serializers.ModelSerializer):
    """Serializer for land plot list view."""
    category_name = serializers.CharField(source='category.name', read_only=True)
    purpose_name = serializers.CharField(source='purpose.name', read_only=True)
    region_name = serializers.CharField(source='region.name', read_only=True)
    district_name = serializers.CharField(source='district.name', read_only=True)
    settlement_name = serializers.CharField(source='settlement.name', read_only=True)
    area_hectares = serializers.ReadOnlyField()
    full_address = serializers.ReadOnlyField()
    owners_count = serializers.SerializerMethodField()
    encumbrances_count = serializers.SerializerMethodField()
    
    class Meta:
        model = LandPlot
        fields = [
            'id', 'cadastral_number', 'region_name', 'district_name',
            'settlement_name', 'address', 'area', 'area_hectares',
            'category_name', 'purpose_name', 'ownership_type',
            'is_verified', 'is_active', 'full_address', 'owners_count',
            'encumbrances_count', 'created_at'
        ]
    
    def get_owners_count(self, obj):
        """Return number of owners."""
        return obj.owners.count()
    
    def get_encumbrances_count(self, obj):
        """Return number of active encumbrances."""
        return obj.encumbrances.filter(is_active=True).count()


class LandPlotSearchSerializer(serializers.Serializer):
    """Serializer for land plot search parameters."""
    query = serializers.CharField(required=False, allow_blank=True)
    cadastral_number = serializers.CharField(required=False, allow_blank=True)
    region = serializers.IntegerField(required=False)
    district = serializers.IntegerField(required=False)
    settlement = serializers.IntegerField(required=False)
    category = serializers.IntegerField(required=False)
    purpose = serializers.IntegerField(required=False)
    ownership_type = serializers.CharField(required=False)
    is_verified = serializers.BooleanField(required=False)
    is_active = serializers.BooleanField(required=False)
    area_min = serializers.DecimalField(required=False, max_digits=12, decimal_places=2)
    area_max = serializers.DecimalField(required=False, max_digits=12, decimal_places=2)
    
    # Geospatial search
    within_geometry = serializers.JSONField(required=False)
    within_distance = serializers.FloatField(required=False)
    center_point = serializers.JSONField(required=False)
    
    # Ordering
    ordering = serializers.CharField(required=False, default='-created_at')
    
    # Pagination
    page = serializers.IntegerField(required=False, default=1)
    page_size = serializers.IntegerField(required=False, default=20)