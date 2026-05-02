from django.urls import path
from . import views

app_name = 'users'

urlpatterns = [
    # Authentication endpoints
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Profile management
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('password/change/', views.PasswordChangeView.as_view(), name='password-change'),
    path('password/reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password/reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('email/verify/', views.EmailVerificationView.as_view(), name='email-verify'),
    
    # Digital signature
    path('digital-signature/upload/', views.DigitalSignatureUploadView.as_view(), name='digital-signature-upload'),
    
    # User metadata endpoints
    path('roles/', views.UserRoleListView.as_view(), name='user-roles'),
    path('sessions/', views.UserSessionListView.as_view(), name='user-sessions'),
    path('activity-logs/', views.UserActivityLogListView.as_view(), name='user-activity-logs'),
]
