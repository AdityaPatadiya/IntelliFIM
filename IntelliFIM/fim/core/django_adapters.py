"""
Adapter to make existing FIM logic work with Django ORM
"""
from django.utils import timezone
from datetime import datetime
import os
from ..models import Directory, FileMetadata, FIMLog


class DjangoDatabaseAdapter:
    """Adapter to replace SQLAlchemy DatabaseOperation with Django ORM"""
    
    def __init__(self, monitored_roots=None):
        self.monitored_roots = monitored_roots or []
    
    def record_file_event(self, directory_path, item_path, item_hash, 
                         item_type, last_modified, status):
        """Record file event in Django database"""
        try:
            # Get or create directory
            directory, created = Directory.objects.get_or_create(
                path=directory_path,
                defaults={'is_active': True}
            )
            
            # Convert last_modified string to datetime if needed
            if isinstance(last_modified, str):
                try:
                    last_modified = datetime.strptime(last_modified, "%Y-%m-%d %H:%M:%S")
                except:
                    last_modified = timezone.now()
            
            # Create file metadata record
            FileMetadata.objects.create(
                directory=directory,
                item_path=item_path,
                item_type=item_type,
                hash=item_hash or '',
                last_modified=last_modified,
                status=status,
                detected_at=timezone.now()
            )
            
            return True
        except Exception as e:
            print(f"Error recording file event: {e}")
            return False
    
    def get_current_baseline(self, directory_path):
        """Get current baseline for directory"""
        try:
            directory = Directory.objects.get(path=directory_path)
            baseline_files = FileMetadata.objects.filter(
                directory=directory,
                status='current'
            )
            
            baseline = {}
            for file_meta in baseline_files:
                baseline[file_meta.item_path] = {
                    'hash': file_meta.hash,
                    'last_modified': file_meta.last_modified,
                    'type': file_meta.item_type
                }
            
            return baseline
        except Directory.DoesNotExist:
            return {}
    
    def delete_directory_records(self, directory_path):
        """Delete all records for a directory"""
        try:
            directory = Directory.objects.get(path=directory_path)
            FileMetadata.objects.filter(directory=directory).delete()
            return True
        except Directory.DoesNotExist:
            return False
    
    def get_all_monitored_directories(self):
        """Get all monitored directories"""
        return list(Directory.objects.values_list('path', flat=True))
