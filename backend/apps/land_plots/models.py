from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.contrib.gis.db import models as gis_models
from django.contrib.gis.geos import Point, Polygon
from django.contrib.gis.measure import Distance
import uuid


class LandCategory(models.Model):
    """Land categories according to Russian classification."""
    
    name = models.CharField(max_length=100, unique=True, verbose_name=_('Category Name'))
    code = models.CharField(max_length=10, unique=True, verbose_name=_('Category Code'))
    description = models.TextField(blank=True, null=True, verbose_name=_('Description'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    class Meta:
        verbose_name = _('Land Category')
        verbose_name_plural = _('Land Categories')
        db_table = 'land_categories'
    
    def __str__(self):
        return f"{self.name} ({self.code})"


class LandPurpose(models.Model):
    """Land purposes according to Russian classification."""
    
    name = models.CharField(max_length=100, unique=True, verbose_name=_('Purpose Name'))
    code = models.CharField(max_length=10, unique=True, verbose_name=_('Purpose Code'))
    description = models.TextField(blank=True, null=True, verbose_name=_('Description'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    class Meta:
        verbose_name = _('Land Purpose')
        verbose_name_plural = _('Land Purposes')
        db_table = 'land_purposes'
    
    def __str__(self):
        return f"{self.name} ({self.code})"


class Region(models.Model):
    """Russian regions (subjects of federation)."""
    
    name = models.CharField(max_length=100, unique=True, verbose_name=_('Region Name'))
    code = models.CharField(max_length=10, unique=True, verbose_name=_('Region Code'))
    okato_code = models.CharField(max_length=15, unique=True, verbose_name=_('OKATO Code'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    class Meta:
        verbose_name = _('Region')
        verbose_name_plural = _('Regions')
        db_table = 'regions'
    
    def __str__(self):
        return self.name


class District(models.Model):
    """Administrative districts within regions."""
    
    region = models.ForeignKey(Region, on_delete=models.CASCADE, related_name='districts')
    name = models.CharField(max_length=100, verbose_name=_('District Name'))
    code = models.CharField(max_length=10, verbose_name=_('District Code'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    class Meta:
        verbose_name = _('District')
        verbose_name_plural = _('Districts')
        db_table = 'districts'
        unique_together = ['region', 'code']
    
    def __str__(self):
        return f"{self.name}, {self.region.name}"


class Settlement(models.Model):
    """Settlements (cities, towns, villages)."""
    
    district = models.ForeignKey(District, on_delete=models.CASCADE, related_name='settlements')
    name = models.CharField(max_length=100, verbose_name=_('Settlement Name'))
    type = models.CharField(max_length=50, verbose_name=_('Settlement Type'))  # город, село, деревня, etc.
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    class Meta:
        verbose_name = _('Settlement')
        verbose_name_plural = _('Settlements')
        db_table = 'settlements'
        unique_together = ['district', 'name']
    
    def __str__(self):
        return f"{self.type} {self.name}, {self.district.name}"


class LandPlot(models.Model):
    """Main land plot model."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Cadastral information
    cadastral_number = models.CharField(
        max_length=50,
        unique=True,
        validators=[RegexValidator(
            regex=r'^\d{2}:\d{2}:\d{6,7}:\d{1,6}$',
            message=_('Invalid cadastral number format. Expected format: XX:XX:XXXXXXX:XXXX')
        )],
        verbose_name=_('Cadastral Number')
    )
    
    # Location information
    region = models.ForeignKey(Region, on_delete=models.PROTECT, verbose_name=_('Region'))
    district = models.ForeignKey(District, on_delete=models.PROTECT, verbose_name=_('District'))
    settlement = models.ForeignKey(Settlement, on_delete=models.PROTECT, verbose_name=_('Settlement'))
    address = models.TextField(verbose_name=_('Address'))
    
    # Land characteristics
    area = models.DecimalField(
        max_digits=12,
        decimal_places=2,
        validators=[MinValueValidator(0.01)],
        verbose_name=_('Area (sq.m.)')
    )
    category = models.ForeignKey(LandCategory, on_delete=models.PROTECT, verbose_name=_('Land Category'))
    purpose = models.ForeignKey(LandPurpose, on_delete=models.PROTECT, verbose_name=_('Land Purpose'))
    
    # Geospatial data
    geometry = gis_models.PolygonField(verbose_name=_('Land Plot Geometry'))
    centroid = gis_models.PointField(verbose_name=_('Land Plot Center'))
    
    # Ownership information
    ownership_type = models.CharField(
        max_length=20,
        choices=[
            ('state', _('State')),
            ('municipal', _('Municipal')),
            ('private', _('Private')),
            ('shared', _('Shared')),
        ],
        default='private',
        verbose_name=_('Ownership Type')
    )
    
    # Status and verification
    is_verified = models.BooleanField(default=False, verbose_name=_('Is Verified'))
    verification_date = models.DateTimeField(null=True, blank=True, verbose_name=_('Verification Date'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    # Additional information
    notes = models.TextField(blank=True, null=True, verbose_name=_('Notes'))
    
    # Metadata
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_land_plots',
        verbose_name=_('Created By')
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))
    
    class Meta:
        verbose_name = _('Land Plot')
        verbose_name_plural = _('Land Plots')
        db_table = 'land_plots'
        indexes = [
            models.Index(fields=['cadastral_number']),
            models.Index(fields=['region', 'district', 'settlement']),
            models.Index(fields=['category', 'purpose']),
            models.Index(fields=['is_verified', 'is_active']),
        ]
    
    def __str__(self):
        return f"Land Plot {self.cadastral_number} ({self.area} m²)"
    
    def save(self, *args, **kwargs):
        # Calculate centroid if geometry is provided
        if self.geometry and not self.centroid:
            self.centroid = self.geometry.centroid
        super().save(*args, **kwargs)
    
    @property
    def area_hectares(self):
        """Return area in hectares."""
        return self.area / 10000
    
    @property
    def full_address(self):
        """Return full address."""
        return f"{self.settlement.name}, {self.settlement.district.region.name}, {self.address}"


class LandPlotOwner(models.Model):
    """Land plot ownership information."""
    
    land_plot = models.ForeignKey(LandPlot, on_delete=models.CASCADE, related_name='owners')
    owner = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='owned_land_plots')
    ownership_share = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0.01), MaxValueValidator(100.00)],
        verbose_name=_('Ownership Share (%)')
    )
    ownership_type = models.CharField(
        max_length=20,
        choices=[
            ('full', _('Full Ownership')),
            ('joint', _('Joint Ownership')),
            ('shared', _('Shared Ownership')),
        ],
        default='full',
        verbose_name=_('Ownership Type')
    )
    is_primary_owner = models.BooleanField(default=False, verbose_name=_('Is Primary Owner'))
    
    # Document information
    ownership_document_number = models.CharField(max_length=50, blank=True, null=True, verbose_name=_('Ownership Document Number'))
    ownership_document_date = models.DateField(null=True, blank=True, verbose_name=_('Ownership Document Date'))
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))
    
    class Meta:
        verbose_name = _('Land Plot Owner')
        verbose_name_plural = _('Land Plot Owners')
        db_table = 'land_plot_owners'
        unique_together = ['land_plot', 'owner']
    
    def __str__(self):
        return f"{self.owner.full_name} - {self.land_plot.cadastral_number} ({self.ownership_share}%)"


class LandPlotDocument(models.Model):
    """Documents related to land plots."""
    
    land_plot = models.ForeignKey(LandPlot, on_delete=models.CASCADE, related_name='documents')
    
    DOCUMENT_TYPES = [
        ('cadastral_passport', _('Cadastral Passport')),
        ('ownership_certificate', _('Ownership Certificate')),
        ('land_use_plan', _('Land Use Plan')),
        ('building_permit', _('Building Permit')),
        ('technical_passport', _('Technical Passport')),
        ('survey_plan', _('Survey Plan')),
        ('other', _('Other')),
    ]
    
    document_type = models.CharField(max_length=50, choices=DOCUMENT_TYPES, verbose_name=_('Document Type'))
    document_number = models.CharField(max_length=50, blank=True, null=True, verbose_name=_('Document Number'))
    document_date = models.DateField(null=True, blank=True, verbose_name=_('Document Date'))
    issued_by = models.CharField(max_length=255, blank=True, null=True, verbose_name=_('Issued By'))
    
    # File information
    file = models.FileField(upload_to='land_plot_documents/', verbose_name=_('Document File'))
    file_name = models.CharField(max_length=255, verbose_name=_('File Name'))
    file_size = models.PositiveIntegerField(verbose_name=_('File Size (bytes)'))
    file_hash = models.CharField(max_length=64, verbose_name=_('File Hash'))
    
    # Additional information
    description = models.TextField(blank=True, null=True, verbose_name=_('Description'))
    is_verified = models.BooleanField(default=False, verbose_name=_('Is Verified'))
    
    # Metadata
    uploaded_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='uploaded_land_plot_documents',
        verbose_name=_('Uploaded By')
    )
    uploaded_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Uploaded At'))
    
    class Meta:
        verbose_name = _('Land Plot Document')
        verbose_name_plural = _('Land Plot Documents')
        db_table = 'land_plot_documents'
    
    def __str__(self):
        return f"{self.get_document_type_display()} - {self.land_plot.cadastral_number}"


class LandPlotEncumbrance(models.Model):
    """Encumbrances on land plots (mortgage, lease, etc.)."""
    
    land_plot = models.ForeignKey(LandPlot, on_delete=models.CASCADE, related_name='encumbrances')
    
    ENCUMBRANCE_TYPES = [
        ('mortgage', _('Mortgage')),
        ('lease', _('Lease')),
        ('servitude', _('Servitude')),
        ('arrest', _('Arrest')),
        ('restriction', _('Restriction')),
        ('other', _('Other')),
    ]
    
    encumbrance_type = models.CharField(max_length=20, choices=ENCUMBRANCE_TYPES, verbose_name=_('Encumbrance Type'))
    description = models.TextField(verbose_name=_('Description'))
    
    # Registration information
    registration_number = models.CharField(max_length=50, blank=True, null=True, verbose_name=_('Registration Number'))
    registration_date = models.DateField(null=True, blank=True, verbose_name=_('Registration Date'))
    
    # Period information
    start_date = models.DateField(verbose_name=_('Start Date'))
    end_date = models.DateField(null=True, blank=True, verbose_name=_('End Date'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    # Related parties
    beneficiary = models.CharField(max_length=255, blank=True, null=True, verbose_name=_('Beneficiary'))
    
    # Metadata
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_encumbrances',
        verbose_name=_('Created By')
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))
    
    class Meta:
        verbose_name = _('Land Plot Encumbrance')
        verbose_name_plural = _('Land Plot Encumbrances')
        db_table = 'land_plot_encumbrances'
    
    def __str__(self):
        return f"{self.get_encumbrance_type_display()} - {self.land_plot.cadastral_number}"


class LandPlotValuation(models.Model):
    """Land plot valuation information."""
    
    land_plot = models.ForeignKey(LandPlot, on_delete=models.CASCADE, related_name='valuations')
    
    VALUATION_TYPES = [
        ('market', _('Market Value')),
        ('cadastral', _('Cadastral Value')),
        ('investment', _('Investment Value')),
        ('mortgage', _('Mortgage Value')),
    ]
    
    valuation_type = models.CharField(max_length=20, choices=VALUATION_TYPES, verbose_name=_('Valuation Type'))
    value = models.DecimalField(max_digits=15, decimal_places=2, verbose_name=_('Value (RUB)'))
    valuation_date = models.DateField(verbose_name=_('Valuation Date'))
    
    # Valuation information
    valuator = models.CharField(max_length=255, blank=True, null=True, verbose_name=_('Valuator'))
    valuation_report_number = models.CharField(max_length=50, blank=True, null=True, verbose_name=_('Valuation Report Number'))
    
    # Additional information
    notes = models.TextField(blank=True, null=True, verbose_name=_('Notes'))
    
    # Metadata
    created_by = models.ForeignKey(
        'users.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_valuations',
        verbose_name=_('Created By')
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    
    class Meta:
        verbose_name = _('Land Plot Valuation')
        verbose_name_plural = _('Land Plot Valuations')
        db_table = 'land_plot_valuations'
        unique_together = ['land_plot', 'valuation_type', 'valuation_date']
    
    def __str__(self):
        return f"{self.get_valuation_type_display()} - {self.land_plot.cadastral_number} - {self.value} RUB"