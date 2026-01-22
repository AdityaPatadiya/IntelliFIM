"""
Django-integrated utility functions for File Integrity Monitoring (FIM)
including hash calculations and directory tracking.
"""
import os
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

from django.utils import timezone
from django.db import transaction

try:
    from fim.models import FileMetadata, Directory, FIMLog
except ImportError:
    pass


class FIMMonitor:
    """Django-integrated FIM monitor for hash calculations and directory tracking"""
    
    def __init__(self, username: str = 'system'):
        self.username = username
    
    def get_formatted_time(self, timestamp: Optional[float] = None) -> str:
        """Convert timestamp to a readable format using Django timezone"""
        if timestamp is None:
            timestamp = time.time()
        
        dt = datetime.fromtimestamp(timestamp, tz=timezone.get_current_timezone())
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    
    def get_formatted_datetime(self, dt: datetime) -> str:
        """Format Django datetime object"""
        return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""
    
    @transaction.atomic
    def track_directory(self, directory_path: str, username: str = None) -> Dict[str, Dict[str, Any]]:
        """
        Track the monitored directory and store baseline in Django database.
        Returns a dictionary of file/folder metadata.
        """
        if username is None:
            username = self.username
        
        current_entries = {}
        
        try:
            dir_obj, created = Directory.objects.get_or_create(
                path=os.path.normpath(directory_path),
                defaults={
                    'is_active': True,
                    'recursive': True,
                    'scan_interval': 300,
                    'last_scan': timezone.now()
                }
            )
            
            for root, dirs, files in os.walk(directory_path):
                for folder in dirs:
                    folder_path = os.path.join(root, folder)
                    self._process_directory_entry(folder_path, directory_path, dir_obj, current_entries, username)
                
                for file in files:
                    file_path = os.path.join(root, file)
                    self._process_file_entry(file_path, directory_path, dir_obj, current_entries, username)
            
            dir_obj.last_scan = timezone.now()
            dir_obj.save()
            
            FIMLog.objects.create(
                log_type='scan',
                level='info',
                message=f"Directory baseline scan completed: {directory_path}",
                directory=dir_obj,
                username=username,
                details={'entries_count': len(current_entries)}
            )
            
            return current_entries
            
        except Exception as e:
            # Log error
            FIMLog.objects.create(
                log_type='scan',
                level='error',
                message=f"Directory scan failed: {directory_path}",
                username=username,
                details={'error': str(e), 'directory': directory_path}
            )
            raise
    
    def _process_directory_entry(self, folder_path: str, base_directory: str, 
                                directory_obj, current_entries: Dict, username: str):
        """Process a directory entry"""
        try:
            rel_path = os.path.relpath(folder_path, base_directory)
            
            folder_hash = self.calculate_folder_hash(folder_path)
            if not folder_hash:
                folder_hash = hashlib.sha256(folder_path.encode()).hexdigest()
            
            try:
                mtime = os.path.getmtime(folder_path)
                last_modified = self.get_formatted_time(mtime)
            except Exception:
                last_modified = self.get_formatted_time()
            
            current_entries[rel_path] = {
                "type": "directory",
                "hash": folder_hash,
                "last_modified": last_modified,
                "full_path": folder_path
            }
            
            FileMetadata.objects.update_or_create(
                directory=directory_obj,
                item_path=rel_path,
                defaults={
                    'item_type': 'directory',
                    'hash': folder_hash,
                    'last_modified': last_modified,
                    'status': 'current',
                    'detected_at': timezone.now()
                }
            )
            
        except Exception as e:
            FIMLog.objects.create(
                log_type='system',
                level='warning',
                message=f"Failed to process directory entry: {folder_path}",
                username=username,
                details={'error': str(e)}
            )
    
    def _process_file_entry(self, file_path: str, base_directory: str, 
                           directory_obj, current_entries: Dict, username: str):
        """Process a file entry"""
        try:
            rel_path = os.path.relpath(file_path, base_directory)
            
            file_hash = self.calculate_hash(file_path)
            if not file_hash:
                file_hash = hashlib.sha256(file_path.encode()).hexdigest()
            
            try:
                mtime = os.path.getmtime(file_path)
                last_modified = self.get_formatted_time(mtime)
                size = os.path.getsize(file_path)
            except Exception:
                last_modified = self.get_formatted_time()
                size = 0
            
            current_entries[rel_path] = {
                "type": "file",
                "hash": file_hash,
                "size": size,
                "last_modified": last_modified,
                "full_path": file_path
            }
            
            FileMetadata.objects.update_or_create(
                directory=directory_obj,
                item_path=rel_path,
                defaults={
                    'item_type': 'file',
                    'hash': file_hash,
                    'size': size,
                    'last_modified': last_modified,
                    'status': 'current',
                    'detected_at': timezone.now()
                }
            )
            
        except Exception as e:
            FIMLog.objects.create(
                log_type='system',
                level='warning',
                message=f"Failed to process file entry: {file_path}",
                username=username,
                details={'error': str(e)}
            )
    
    # ---------------- Hash Functions ----------------
    
    def calculate_hash(self, file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate the hash of a file"""
        try:
            if not os.path.exists(file_path):
                return None
            
            hash_func = getattr(hashlib, algorithm, hashlib.sha256)()
            
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
            
        except (IsADirectoryError, FileNotFoundError, PermissionError, OSError) as e:
            return None
        except Exception as e:
            return None
    
    def calculate_folder_hash(self, folder_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate the hash of a folder including subfolders and files"""
        try:
            if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
                return None
            
            hash_func = getattr(hashlib, algorithm, hashlib.sha256)()
            folder = Path(folder_path)
            
            hash_func.update(folder.name.encode())
            
            entries = []
            try:
                for entry in folder.iterdir():
                    entries.append(entry)
                entries.sort(key=lambda x: x.name)
            except Exception:
                return hash_func.hexdigest()
            
            for entry in entries:
                hash_func.update(entry.name.encode())
                
                if entry.is_dir():
                    subfolder_hash = self.calculate_folder_hash(str(entry), algorithm)
                    if subfolder_hash:
                        hash_func.update(subfolder_hash.encode())
                elif entry.is_file():
                    file_hash = self.calculate_hash(str(entry), algorithm)
                    if file_hash:
                        hash_func.update(file_hash.encode())
            
            return hash_func.hexdigest()
            
        except Exception:
            return None
    
    def calculate_hash_for_backup(self, path: str, is_directory: bool = False) -> Optional[str]:
        """Convenience method for backup operations"""
        if is_directory:
            return self.calculate_folder_hash(path)
        else:
            return self.calculate_hash(path)
    
    def compare_files(self, file1_path: str, file2_path: str) -> bool:
        """Compare two files by hash"""
        hash1 = self.calculate_hash(file1_path)
        hash2 = self.calculate_hash(file2_path)
        
        if not hash1 or not hash2:
            return False
        
        return hash1 == hash2
    
    def get_file_metadata(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a file"""
        try:
            if not os.path.exists(file_path):
                return None
            
            stats = os.stat(file_path)
            
            return {
                'path': file_path,
                'size': stats.st_size,
                'last_modified': datetime.fromtimestamp(stats.st_mtime, tz=timezone.get_current_timezone()),
                'created': datetime.fromtimestamp(stats.st_ctime, tz=timezone.get_current_timezone()),
                'hash': self.calculate_hash(file_path),
                'is_file': os.path.isfile(file_path),
                'is_dir': os.path.isdir(file_path)
            }
        except Exception:
            return None
    
    def scan_directory_for_changes(self, directory_path: str, baseline: Dict[str, str]) -> Dict[str, List[str]]:
        """
        Scan directory and compare with baseline hashes
        
        Args:
            directory_path: Path to scan
            baseline: Dictionary of {relative_path: hash}
            
        Returns:
            Dict with lists of added, modified, deleted files
        """
        current_files = {}
        
        # Get current state
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, directory_path)
                
                file_hash = self.calculate_hash(file_path)
                if file_hash:
                    current_files[rel_path] = file_hash
        
        # Compare with baseline
        added = [path for path in current_files if path not in baseline]
        deleted = [path for path in baseline if path not in current_files]
        modified = [
            path for path in current_files 
            if path in baseline and current_files[path] != baseline[path]
        ]
        
        return {
            'added': added,
            'deleted': deleted,
            'modified': modified,
            'unchanged': [path for path in current_files if path in baseline and current_files[path] == baseline[path]]
        }


# Helper functions for easy use
def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate hash of a single file"""
    fim = FIMMonitor()
    return fim.calculate_hash(file_path, algorithm)


def calculate_folder_hash(folder_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate hash of a folder"""
    fim = FIMMonitor()
    return fim.calculate_folder_hash(folder_path, algorithm)


def scan_directory(directory_path: str, username: str = 'system') -> Dict[str, Dict[str, Any]]:
    """Convenience function to scan directory and store baseline"""
    fim = FIMMonitor(username)
    return fim.track_directory(directory_path, username)
