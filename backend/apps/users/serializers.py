from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User, UserProfile, UserRole, UserSession, UserActivityLog


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name', 'patronymic',
            'phone', 'password', 'password_confirm', 'company_name',
            'company_inn', 'company_ogrn'
        ]
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    email = serializers.EmailField()
    password = serializers.CharField()
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            user = authenticate(
                request=self.context.get('request'),
                username=email,
                password=password
            )
            
            if not user:
                raise serializers.ValidationError('Invalid credentials')
            
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled')
            
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Must include email and password')


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile."""
    full_name = serializers.ReadOnlyField()
    is_certificate_valid = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'patronymic',
            'phone', 'birth_date', 'is_verified', 'verification_date',
            'company_name', 'company_inn', 'company_ogrn',
            'has_digital_signature', 'certificate_issued_date', 'certificate_expires_date',
            'full_name', 'is_certificate_valid', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'is_verified', 'verification_date', 'created_at', 'updated_at']


class UserProfileDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for user profile with extended information."""
    profile = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    full_name = serializers.ReadOnlyField()
    is_certificate_valid = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'patronymic',
            'phone', 'birth_date', 'is_verified', 'verification_date',
            'company_name', 'company_inn', 'company_ogrn',
            'has_digital_signature', 'certificate_issued_date', 'certificate_expires_date',
            'full_name', 'is_certificate_valid', 'profile', 'roles',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'is_verified', 'verification_date', 'created_at', 'updated_at']
    
    def get_profile(self, obj):
        try:
            profile = obj.profile
            return UserProfileExtendedSerializer(profile).data
        except UserProfile.DoesNotExist:
            return None
    
    def get_roles(self, obj):
        roles = obj.roles.filter(is_active=True)
        return UserRoleSerializer(roles, many=True).data


class UserProfileExtendedSerializer(serializers.ModelSerializer):
    """Serializer for extended user profile information."""
    
    class Meta:
        model = UserProfile
        fields = [
            'address', 'postal_code', 'city', 'region', 'language', 'timezone',
            'email_notifications', 'sms_notifications', 'passport_scan', 'inn_scan',
            'created_at', 'updated_at'
        ]


class UserRoleSerializer(serializers.ModelSerializer):
    """Serializer for user roles."""
    assigned_by_name = serializers.CharField(source='assigned_by.full_name', read_only=True)
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    
    class Meta:
        model = UserRole
        fields = [
            'id', 'role', 'role_display', 'assigned_by', 'assigned_by_name',
            'assigned_at', 'expires_at', 'is_active'
        ]
        read_only_fields = ['id', 'assigned_at']


class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for user sessions."""
    user_name = serializers.CharField(source='user.full_name', read_only=True)
    
    class Meta:
        model = UserSession
        fields = [
            'id', 'user', 'user_name', 'session_key', 'ip_address',
            'user_agent', 'is_active', 'created_at', 'last_activity', 'expires_at'
        ]
        read_only_fields = ['id', 'created_at', 'last_activity']


class UserActivityLogSerializer(serializers.ModelSerializer):
    """Serializer for user activity logs."""
    user_name = serializers.CharField(source='user.full_name', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = UserActivityLog
        fields = [
            'id', 'user', 'user_name', 'action', 'action_display',
            'object_type', 'object_id', 'description', 'ip_address',
            'user_agent', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for password change."""
    current_password = serializers.CharField()
    new_password = serializers.CharField(validators=[validate_password])
    new_password_confirm = serializers.CharField()
    
    def validate_current_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Current password is incorrect')
        return value
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        return attrs


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset request."""
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError('User with this email does not exist')
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation."""
    token = serializers.CharField()
    new_password = serializers.CharField(validators=[validate_password])
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification."""
    token = serializers.CharField()


class DigitalSignatureUploadSerializer(serializers.Serializer):
    """Serializer for digital signature upload."""
    certificate_file = serializers.FileField()
    password = serializers.CharField()
    
    def validate_certificate_file(self, value):
        # Validate file type and size
        allowed_extensions = ['.p12', '.pfx']
        file_extension = value.name.split('.')[-1].lower()
        
        if f'.{file_extension}' not in allowed_extensions:
            raise serializers.ValidationError(
                f'Invalid file format. Allowed formats: {", ".join(allowed_extensions)}'
            )
        
        if value.size > 10 * 1024 * 1024:  # 10MB limit
            raise serializers.ValidationError('File size too large. Maximum size is 10MB')
        
        return value