from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator
import uuid


class User(AbstractUser):
    """Extended user model with additional fields for land contract system."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    phone = models.CharField(
        max_length=20,
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$',
            message=_("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed.")
        )],
        blank=True,
        null=True
    )
    
    # Profile fields
    patronymic = models.CharField(max_length=150, blank=True, null=True, verbose_name=_('Patronymic'))
    birth_date = models.DateField(null=True, blank=True, verbose_name=_('Birth Date'))
    
    # Professional fields
    is_verified = models.BooleanField(default=False, verbose_name=_('Is Verified'))
    verification_date = models.DateTimeField(null=True, blank=True, verbose_name=_('Verification Date'))
    
    # Company information
    company_name = models.CharField(max_length=255, blank=True, null=True, verbose_name=_('Company Name'))
    company_inn = models.CharField(max_length=12, blank=True, null=True, verbose_name=_('Company INN'))
    company_ogrn = models.CharField(max_length=13, blank=True, null=True, verbose_name=_('Company OGRN'))
    
    # Digital signature
    has_digital_signature = models.BooleanField(default=False, verbose_name=_('Has Digital Signature'))
    certificate_issued_date = models.DateField(null=True, blank=True, verbose_name=_('Certificate Issued Date'))
    certificate_expires_date = models.DateField(null=True, blank=True, verbose_name=_('Certificate Expires Date'))
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']
    
    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        db_table = 'users'
    
    def __str__(self):
        return f"{self.last_name} {self.first_name} {self.patronymic or ''}".strip()
    
    @property
    def full_name(self):
        """Return user's full name."""
        return f"{self.last_name} {self.first_name} {self.patronymic or ''}".strip()
    
    @property
    def is_certificate_valid(self):
        """Check if digital certificate is still valid."""
        if not self.certificate_expires_date:
            return False
        from django.utils import timezone
        return self.certificate_expires_date > timezone.now().date()


class UserProfile(models.Model):
    """Extended user profile with additional information."""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Address information
    address = models.TextField(blank=True, null=True, verbose_name=_('Address'))
    postal_code = models.CharField(max_length=10, blank=True, null=True, verbose_name=_('Postal Code'))
    city = models.CharField(max_length=100, blank=True, null=True, verbose_name=_('City'))
    region = models.CharField(max_length=100, blank=True, null=True, verbose_name=_('Region'))
    
    # Preferences
    language = models.CharField(max_length=10, default='ru', verbose_name=_('Language'))
    timezone = models.CharField(max_length=50, default='Europe/Moscow', verbose_name=_('Timezone'))
    email_notifications = models.BooleanField(default=True, verbose_name=_('Email Notifications'))
    sms_notifications = models.BooleanField(default=False, verbose_name=_('SMS Notifications'))
    
    # Additional documents
    passport_scan = models.FileField(upload_to='documents/passports/', blank=True, null=True, verbose_name=_('Passport Scan'))
    inn_scan = models.FileField(upload_to='documents/inn/', blank=True, null=True, verbose_name=_('INN Scan'))
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_('Updated At'))
    
    class Meta:
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')
        db_table = 'user_profiles'
    
    def __str__(self):
        return f"Profile of {self.user.full_name}"


class UserRole(models.Model):
    """User roles for permission management."""
    
    ROLE_CHOICES = [
        ('client', _('Client')),
        ('realtor', _('Realtor')),
        ('lawyer', _('Lawyer')),
        ('notary', _('Notary')),
        ('company_admin', _('Company Administrator')),
        ('system_admin', _('System Administrator')),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='roles')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, verbose_name=_('Role'))
    assigned_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='assigned_roles',
        verbose_name=_('Assigned By')
    )
    assigned_at = models.DateTimeField(auto_now_add=True, verbose_name=_('Assigned At'))
    expires_at = models.DateTimeField(null=True, blank=True, verbose_name=_('Expires At'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is Active'))
    
    class Meta:
        verbose_name = _('User Role')
        verbose_name_plural = _('User Roles')
        db_table = 'user_roles'
        unique_together = ['user', 'role']
    
    def __str__(self):
        return f"{self.user.full_name} - {self.get_role_display()}"


class UserSession(models.Model):
    """Track user sessions for security and analytics."""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(max_length=40, unique=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        verbose_name = _('User Session')
        verbose_name_plural = _('User Sessions')
        db_table = 'user_sessions'
    
    def __str__(self):
        return f"Session for {self.user.full_name} from {self.ip_address}"


class UserActivityLog(models.Model):
    """Log user activities for audit and security."""
    
    ACTION_CHOICES = [
        ('login', _('Login')),
        ('logout', _('Logout')),
        ('create_contract', _('Create Contract')),
        ('sign_contract', _('Sign Contract')),
        ('upload_document', _('Upload Document')),
        ('view_contract', _('View Contract')),
        ('edit_contract', _('Edit Contract')),
        ('delete_contract', _('Delete Contract')),
        ('create_land_plot', _('Create Land Plot')),
        ('edit_land_plot', _('Edit Land Plot')),
        ('delete_land_plot', _('Delete Land Plot')),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activities')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, verbose_name=_('Action'))
    object_type = models.CharField(max_length=50, blank=True, null=True, verbose_name=_('Object Type'))
    object_id = models.CharField(max_length=50, blank=True, null=True, verbose_name=_('Object ID'))
    description = models.TextField(blank=True, null=True, verbose_name=_('Description'))
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name=_('Timestamp'))
    
    class Meta:
        verbose_name = _('User Activity Log')
        verbose_name_plural = _('User Activity Logs')
        db_table = 'user_activity_logs'
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.user.full_name} - {self.get_action_display()} at {self.timestamp}"