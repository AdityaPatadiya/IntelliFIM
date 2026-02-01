from rest_framework import permissions
from rest_framework.permissions import BasePermission


class IsAdminOrAnalystUser(BasePermission):
    """
    Allows access only to admin or analyst users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and 
                   request.user.role in ['admin', 'analyst'])


class IsAdminUser(BasePermission):
    """
    Allows access only to admin users.
    """
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and 
                   request.user.role == 'admin')
