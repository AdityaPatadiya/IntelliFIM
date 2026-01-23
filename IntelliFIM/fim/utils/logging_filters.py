"""
Custom logging filters for Django
"""
import logging
from django.utils import timezone
from threading import local

_thread_locals = local()

class UsernameFilter(logging.Filter):
    """Add username to log records"""
    def filter(self, record):
        record.username = getattr(_thread_locals, 'username', 'system')
        return True

def set_current_user(username):
    """Set current user for thread-local logging"""
    _thread_locals.username = username

def clear_current_user():
    """Clear current user from thread-local"""
    if hasattr(_thread_locals, 'username'):
        delattr(_thread_locals, 'username')
