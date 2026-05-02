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
        return bool(
            user and user.is_authenticated and obj.status == 'pending_signature' and (
                obj.seller_id == user.id or obj.buyer_id == user.id
            )
        )
