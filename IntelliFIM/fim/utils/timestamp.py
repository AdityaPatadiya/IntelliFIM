from django.utils import timezone
from datetime import datetime

def get_timestamp_with_timezone():
    """Get current timestamp with timezone info"""
    now = timezone.now()
    return now.strftime("%Y-%m-%d %H:%M:%S"), now.tzinfo

def get_current_timestamp():
    """Get current timestamp string"""
    return timezone.now().strftime("%Y-%m-%d %H:%M:%S")
