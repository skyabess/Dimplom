from rest_framework.permissions import BasePermission


class CanViewContract(BasePermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        return bool(
            user and user.is_authenticated and (
                user.is_staff or obj.seller_id == user.id or obj.buyer_id == user.id
            )
        )


class CanSignContract(BasePermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        manager_roles = {'system_admin', 'company_admin', 'lawyer', 'realtor', 'notary'}
        has_manager_role = (
            user and user.is_authenticated and hasattr(user, 'roles') and
            user.roles.filter(role__in=manager_roles, is_active=True).exists()
        )

        return bool(
            user and user.is_authenticated and obj.status == 'pending_signature' and (
                user.is_staff or
                user.is_superuser or
                has_manager_role or
                obj.seller_id == user.id or
                obj.buyer_id == user.id
            )
        )
