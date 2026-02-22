from rest_framework import generics, status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, logout
from django.utils import timezone
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import logging

from .models import User, UserProfile, UserRole, UserSession, UserActivityLog
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,
    UserProfileDetailSerializer, UserRoleSerializer, UserSessionSerializer,
    UserActivityLogSerializer, PasswordChangeSerializer, PasswordResetSerializer,
    PasswordResetConfirmSerializer, EmailVerificationSerializer,
    DigitalSignatureUploadSerializer
)
from .permissions import IsOwnerOrReadOnly, IsAdminUser

logger = logging.getLogger(__name__)


class UserRegistrationView(generics.CreateAPIView):
    """User registration endpoint."""
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Register a new user",
        responses={201: UserProfileSerializer()}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        with transaction.atomic():
            user = serializer.save()
            
            # Create user profile
            UserProfile.objects.create(user=user)
            
            # Log activity
            UserActivityLog.objects.create(
                user=user,
                action='login',
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description='User registration'
            )
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'user': UserProfileSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserLoginView(generics.GenericAPIView):
    """User login endpoint."""
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Login user and return JWT tokens",
        responses={200: UserProfileSerializer()}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        
        # Create user session
        session = UserSession.objects.create(
            user=user,
            session_key=request.session.session_key or '',
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            expires_at=timezone.now() + timezone.timedelta(days=30)
        )
        
        # Log activity
        UserActivityLog.objects.create(
            user=user,
            action='login',
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            description=f'Login from session {session.session_key}'
        )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'user': UserProfileDetailSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'session_id': session.id
        })
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def logout_view(request):
    """Logout user and invalidate session."""
    try:
        # Deactivate user session
        session_id = request.data.get('session_id')
        if session_id:
            UserSession.objects.filter(
                id=session_id,
                user=request.user
            ).update(is_active=False)
        
        # Log activity
        UserActivityLog.objects.create(
            user=request.user,
            action='logout',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            description='User logout'
        )
        
        return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return Response(
            {'error': 'Logout failed'}, 
            status=status.HTTP_400_BAD_REQUEST
        )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """User profile view and update."""
    serializer_class = UserProfileDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_object(self):
        return self.request.user
    
    @swagger_auto_schema(
        operation_description="Get user profile",
        responses={200: UserProfileDetailSerializer()}
    )
    def get(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        operation_description="Update user profile",
        responses={200: UserProfileDetailSerializer()}
    )
    def patch(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # Log activity
        UserActivityLog.objects.create(
            user=user,
            action='edit_profile',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            description='Profile updated'
        )
        
        return Response(serializer.data)


class PasswordChangeView(generics.GenericAPIView):
    """Change user password."""
    serializer_class = PasswordChangeSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Change user password",
        responses={200: "Password changed successfully"}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        # Log activity
        UserActivityLog.objects.create(
            user=user,
            action='password_change',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            description='Password changed'
        )
        
        return Response(
            {'message': 'Password changed successfully'}, 
            status=status.HTTP_200_OK
        )


class PasswordResetView(generics.GenericAPIView):
    """Request password reset."""
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Request password reset",
        responses={200: "Password reset email sent"}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        user = User.objects.get(email=email)
        
        # TODO: Send password reset email
        # This would integrate with your email service
        
        return Response(
            {'message': 'Password reset email sent'}, 
            status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(generics.GenericAPIView):
    """Confirm password reset."""
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Confirm password reset",
        responses={200: "Password reset successfully"}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # TODO: Verify token and reset password
        # This would integrate with your token verification system
        
        return Response(
            {'message': 'Password reset successfully'}, 
            status=status.HTTP_200_OK
        )


class EmailVerificationView(generics.GenericAPIView):
    """Verify user email."""
    serializer_class = EmailVerificationSerializer
    permission_classes = [permissions.AllowAny]
    
    @swagger_auto_schema(
        operation_description="Verify user email",
        responses={200: "Email verified successfully"}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # TODO: Verify email token
        # This would integrate with your email verification system
        
        return Response(
            {'message': 'Email verified successfully'}, 
            status=status.HTTP_200_OK
        )


class DigitalSignatureUploadView(generics.GenericAPIView):
    """Upload digital signature certificate."""
    serializer_class = DigitalSignatureUploadSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Upload digital signature certificate",
        responses={200: "Digital signature uploaded successfully"}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        certificate_file = serializer.validated_data['certificate_file']
        
        # TODO: Process and validate digital signature
        # This would integrate with your digital signature verification system
        
        user.has_digital_signature = True
        user.save()
        
        # Log activity
        UserActivityLog.objects.create(
            user=user,
            action='upload_digital_signature',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            description='Digital signature certificate uploaded'
        )
        
        return Response(
            {'message': 'Digital signature uploaded successfully'}, 
            status=status.HTTP_200_OK
        )


class UserRoleListView(generics.ListCreateAPIView):
    """List and create user roles."""
    serializer_class = UserRoleSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        return UserRole.objects.all().select_related('user', 'assigned_by')
    
    @swagger_auto_schema(
        operation_description="List all user roles",
        responses={200: UserRoleSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    @swagger_auto_schema(
        operation_description="Assign role to user",
        responses={201: UserRoleSerializer()}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        role = serializer.save(assigned_by=request.user)
        
        # Log activity
        UserActivityLog.objects.create(
            user=request.user,
            action='assign_role',
            object_type='UserRole',
            object_id=str(role.id),
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            description=f'Role {role.role} assigned to {role.user.full_name}'
        )
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class UserSessionListView(generics.ListAPIView):
    """List user sessions."""
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return UserSession.objects.filter(
            user=self.request.user
        ).select_related('user')
    
    @swagger_auto_schema(
        operation_description="List user sessions",
        responses={200: UserSessionSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class UserActivityLogListView(generics.ListAPIView):
    """List user activity logs."""
    serializer_class = UserActivityLogSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return UserActivityLog.objects.filter(
            user=self.request.user
        ).select_related('user')
    
    @swagger_auto_schema(
        operation_description="List user activity logs",
        responses={200: UserActivityLogSerializer(many=True)}
    )
    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


def get_client_ip(request):
    """Get client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip