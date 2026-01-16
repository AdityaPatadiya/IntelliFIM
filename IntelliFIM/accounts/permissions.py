from rest_framework import permissions


class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and getattr(request.user, 'is_admin', False)
