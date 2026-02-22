from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    Read-only access is allowed for any request.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner of the object.
        return obj == request.user


class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users.
    """
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            (request.user.is_staff or request.user.is_superuser)
        )


class IsVerifiedUser(permissions.BasePermission):
    """
    Custom permission to only allow verified users.
    """
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.is_verified
        )


class HasDigitalSignature(permissions.BasePermission):
    """
    Custom permission to only allow users with digital signature.
    """
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.has_digital_signature and
            request.user.is_certificate_valid
        )


class IsCompanyAdmin(permissions.BasePermission):
    """
    Custom permission to only allow company administrators.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return request.user.roles.filter(
            role='company_admin',
            is_active=True
        ).exists()


class IsSystemAdmin(permissions.BasePermission):
    """
    Custom permission to only allow system administrators.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return request.user.roles.filter(
            role='system_admin',
            is_active=True
        ).exists()


class IsLawyer(permissions.BasePermission):
    """
    Custom permission to only allow lawyers.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return request.user.roles.filter(
            role='lawyer',
            is_active=True
        ).exists()


class IsNotary(permissions.BasePermission):
    """
    Custom permission to only allow notaries.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return request.user.roles.filter(
            role='notary',
            is_active=True
        ).exists()


class IsRealtor(permissions.BasePermission):
    """
    Custom permission to only allow realtors.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return request.user.roles.filter(
            role='realtor',
            is_active=True
        ).exists()


class IsClient(permissions.BasePermission):
    """
    Custom permission to only allow clients.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return request.user.roles.filter(
            role='client',
            is_active=True
        ).exists()


class CanSignContracts(permissions.BasePermission):
    """
    Custom permission to only allow users who can sign contracts.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        return (
            request.user.has_digital_signature and
            request.user.is_certificate_valid and
            request.user.is_verified
        )


class CanManageContracts(permissions.BasePermission):
    """
    Custom permission to only allow users who can manage contracts.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Check if user has any of the allowed roles
        allowed_roles = ['lawyer', 'notary', 'realtor', 'company_admin', 'system_admin']
        return request.user.roles.filter(
            role__in=allowed_roles,
            is_active=True
        ).exists()


class CanViewContracts(permissions.BasePermission):
    """
    Custom permission to only allow users who can view contracts.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # All authenticated users can view contracts
        return True


class CanManageLandPlots(permissions.BasePermission):
    """
    Custom permission to only allow users who can manage land plots.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # Check if user has any of the allowed roles
        allowed_roles = ['realtor', 'company_admin', 'system_admin']
        return request.user.roles.filter(
            role__in=allowed_roles,
            is_active=True
        ).exists()


class CanViewLandPlots(permissions.BasePermission):
    """
    Custom permission to only allow users who can view land plots.
    """
    
    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        
        # All authenticated users can view land plots
        return True


class IsObjectOwner(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to access it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Check if the object has a user field
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        # Check if the object has an owner field
        if hasattr(obj, 'owner'):
            return obj.owner == request.user
        
        # Check if the object has a created_by field
        if hasattr(obj, 'created_by'):
            return obj.created_by == request.user
        
        # Check if the object is a contract and user is a participant
        if hasattr(obj, 'participants'):
            return request.user in obj.participants.all()
        
        # Check if the object is a contract and user is the creator
        if hasattr(obj, 'creator'):
            return obj.creator == request.user
        
        return False


class IsParticipantOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow participants of an object to edit it.
    Read-only access is allowed for any authenticated request.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any authenticated request
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        
        # Write permissions are only allowed to participants
        if hasattr(obj, 'participants'):
            return request.user in obj.participants.all()
        
        # Check if user is the creator
        if hasattr(obj, 'creator'):
            return obj.creator == request.user
        
        return False