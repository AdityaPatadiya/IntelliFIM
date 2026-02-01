from rest_framework import permissions


class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and getattr(request.user, 'is_admin', False)


class IsAdminOrAnalystUser(permissions.BasePermission):
    """
    Custom permission to allow admin or analyst users.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if hasattr(request.user, 'role'):
            return request.user.role in ['admin', 'analyst']

        return getattr(request.user, 'is_admin', False)
