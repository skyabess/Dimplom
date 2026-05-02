from rest_framework.permissions import IsAuthenticated


class IsOwnerOrReadOnly(IsAuthenticated):
    def has_object_permission(self, request, view, obj):
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True

        owner = getattr(obj, 'owner', None)
        created_by = getattr(obj, 'created_by', None)
        author = getattr(obj, 'author', None)
        return request.user in {owner, created_by, author}
