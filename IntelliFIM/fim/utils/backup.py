"""
Django-integrated backup system for File Integrity Monitoring
"""
import os
import shutil
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from fim.core.fim_utils import FIMMonitor

from django.db import transaction
from django.utils import timezone
from django.conf import settings

try:
    from fim.models import BackupRecord, FileMetadata, Directory, FIMLog
except ImportError:
    pass


class BackupLogData:
    """Simple class to hold backup log data"""
    def __init__(self, auth_user, source_dir, backup_type, backup_status, 
                 backup_duration, files_changes):
        self.auth_user = auth_user
        self.source_dir = source_dir
        self.backup_type = backup_type
        self.backup_status = backup_status
        self.backup_duration = backup_duration
        self.files_changes = files_changes


class Backup:
    """Django-integrated backup system"""
    
    def __init__(self):
        self.backup_root = getattr(settings, 'BACKUP_ROOT', 
                                  os.path.join(settings.BASE_DIR, 'backups'))
        
        # Metadata file for legacy compatibility (optional)
        self.meta_file_path = os.path.join(self.backup_root, 'backup_metadata.json')
        
        os.makedirs(self.backup_root, exist_ok=True)
        
        # Load legacy metadata if exists (for migration purposes)
        self.legacy_metadata = self._load_legacy_metadata()
        self.fim_monitor = FIMMonitor()
    
    def _load_legacy_metadata(self) -> Dict:
        """Load legacy metadata from file (for migration)"""
        try:
            if os.path.exists(self.meta_file_path):
                with open(self.meta_file_path, "r", encoding='utf-8') as f:
                    return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError, UnicodeDecodeError) as e:
            print(f"Warning: Could not load legacy metadata: {e}")
        return {}
    
    def _save_legacy_metadata(self, metadata: Dict):
        """Save legacy metadata (for backward compatibility)"""
        try:
            with open(self.meta_file_path, "w", encoding='utf-8') as f:
                json.dump(metadata, f, indent=4, default=str)
        except Exception as e:
            print(f"Warning: Could not save legacy metadata: {e}")
    
    def compute_file_hash(self, file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Compute hash of a file using FIMMonitor"""
        return self.fim_monitor.calculate_hash(file_path, algorithm)

    def compute_folder_hash(self, folder_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Compute combined hash for all files in a folder using FIMMonitor"""
        return self.fim_monitor.calculate_folder_hash(folder_path, algorithm)
    
    def _log_backup_to_database(self, log_data: BackupLogData):
        """Log backup operation to Django database"""
        try:
            # Get or create directory record
            directory, created = Directory.objects.get_or_create(
                path=log_data.source_dir,
                defaults={
                    'is_active': False,
                    'recursive': True
                }
            )
            
            # Create FIM log entry
            FIMLog.objects.create(
                log_type='backup',
                level='info' if log_data.backup_status == 'success' else 'error',
                message=f"Backup {log_data.backup_status} for {log_data.source_dir}",
                directory=directory,
                username=log_data.auth_user,
                details={
                    'backup_type': log_data.backup_type,
                    'duration_seconds': log_data.backup_duration,
                    'file_changes': log_data.files_changes,
                    'timestamp': timezone.now().isoformat()
                }
            )
            
            return True
        except Exception as e:
            print(f"Error logging to database: {e}")
            # Fallback to legacy logging
            self._log_backup_legacy(log_data)
            return False
    
    def _log_backup_legacy(self, log_data: BackupLogData):
        """Legacy JSON logging (fallback)"""
        try:
            backup_log_path = os.path.join(self.backup_root, 'backup_logs.json')
            
            if os.path.exists(backup_log_path):
                with open(backup_log_path, "r", encoding='utf-8') as f:
                    existing_data = json.load(f)
            else:
                existing_data = []
            
            backup_entry = {
                "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
                "timezone": str(timezone.get_current_timezone()),
                "user": log_data.auth_user,
                "directory": log_data.source_dir,
                "backup_type": log_data.backup_type,
                "status": log_data.backup_status,
                "duration_seconds": log_data.backup_duration,
                "file_changes": log_data.files_changes
            }
            
            existing_data.append(backup_entry)
            
            with open(backup_log_path, "w", encoding='utf-8') as f:
                json.dump(existing_data, f, indent=4, default=str)
                
        except Exception as e:
            print(f"Error in legacy backup logging: {e}")
    
    @transaction.atomic
    def create_backup(self, source_dir: str, username: str, 
                     backup_type: str = 'automatic') -> Optional[Dict]:
        """
        Perform incremental backup using Django ORM
        
        Args:
            source_dir: Directory path to backup
            username: Username performing the backup
            backup_type: Type of backup ('automatic', 'manual', 'restore')
        
        Returns:
            Dict with backup details or None if failed
        """
        start_time = timezone.now()
        
        if not os.path.exists(source_dir):
            print(f"Source directory {source_dir} does not exist.")
            return None
        
        try:
            source_dir = os.path.abspath(source_dir)
            dir_name = os.path.basename(os.path.normpath(source_dir))
            
            # Create timestamped backup directory
            timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
            backup_dir = os.path.join(self.backup_root, dir_name, timestamp)
            os.makedirs(backup_dir, exist_ok=True)
            
            changed_files = []
            new_files = []
            deleted_files = []
            
            # Get or create directory record
            directory, created = Directory.objects.get_or_create(
                path=source_dir,
                defaults={
                    'is_active': False,
                    'recursive': True,
                    'scan_interval': 300
                }
            )
            
            # Get current baseline files from database
            baseline_files = FileMetadata.objects.filter(
                directory=directory,
                status='current'
            )
            
            baseline_dict = {
                file.item_path: {
                    'hash': file.hash,
                    'last_modified': file.last_modified
                }
                for file in baseline_files
            }
            
            # Process files
            for root, dirs, files in os.walk(source_dir):
                relative_root = os.path.relpath(root, source_dir)
                
                for file in files:
                    src_file = os.path.join(root, file)
                    
                    # Get relative path
                    if relative_root == ".":
                        rel_path = file
                    else:
                        rel_path = os.path.join(relative_root, file).replace("\\", "/")
                    
                    dest_file = os.path.join(backup_dir, rel_path)
                    
                    # Compute file hash
                    current_hash = self.compute_file_hash(src_file)
                    if not current_hash:
                        continue
                    
                    # Check if file exists in baseline
                    file_stat = os.stat(src_file)
                    last_modified = datetime.fromtimestamp(file_stat.st_mtime)
                    
                    baseline_info = baseline_dict.get(rel_path)
                    
                    if not baseline_info:
                        # New file
                        new_files.append(rel_path)
                    elif (current_hash != baseline_info['hash'] or 
                          last_modified > baseline_info['last_modified']):
                        # Changed file
                        changed_files.append(rel_path)
                    
                    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                    shutil.copy2(src_file, dest_file)
                    
                    file_metadata, created = FileMetadata.objects.update_or_create(
                        directory=directory,
                        item_path=rel_path,
                        defaults={
                            'hash': current_hash,
                            'size': file_stat.st_size,
                            'last_modified': last_modified,
                            'item_type': 'file',
                            'status': 'current'
                        }
                    )
            
            # Check for deleted files (in baseline but not on disk)
            existing_files = set()
            for root, dirs, files in os.walk(source_dir):
                relative_root = os.path.relpath(root, source_dir)
                for file in files:
                    if relative_root == ".":
                        rel_path = file
                    else:
                        rel_path = os.path.join(relative_root, file).replace("\\", "/")
                    existing_files.add(rel_path)
            
            deleted_files = [path for path in baseline_dict.keys() 
                           if path not in existing_files]
            
            backup_record = BackupRecord.objects.create(
                backup_type=backup_type,
                original_path=source_dir,
                backup_path=backup_dir,
                hash=self.compute_folder_hash(backup_dir) or '',
                size=sum(os.path.getsize(os.path.join(backup_dir, f)) 
                        for f in os.listdir(backup_dir) 
                        if os.path.isfile(os.path.join(backup_dir, f))),
                file_metadata=FileMetadata.objects.filter(
                    directory=directory,
                    status='current'
                ).first(),  # Link to first file metadata for reference
                backed_up_by=username,
                expires_at=timezone.now() + timedelta(days=30)  # Default 30-day retention
            )
            
            duration = (timezone.now() - start_time).total_seconds()
            
            log_data = BackupLogData(
                auth_user=username,
                source_dir=source_dir,
                backup_type=backup_type,
                backup_status="success",
                backup_duration=duration,
                files_changes={
                    "new": new_files,
                    "changed": changed_files,
                    "deleted": deleted_files,
                    "total_backed_up": len(new_files) + len(changed_files)
                }
            )
            
            self._log_backup_to_database(log_data)
            
            print(f"\n{'='*50}")
            print("Backup Complete!")
            print(f"{'='*50}")
            print(f"Source: {source_dir}")
            print(f"Backup: {backup_dir}")
            print(f"Type: {backup_type}")
            print(f"New files: {len(new_files)}")
            print(f"Changed files: {len(changed_files)}")
            print(f"Deleted files: {len(deleted_files)}")
            print(f"Duration: {duration:.2f} seconds")
            print(f"Backup ID: {backup_record.id}")
            print(f"{'='*50}\n")
            
            return {
                'backup_id': backup_record.id,
                'backup_path': backup_dir,
                'backup_type': backup_type,
                'new_files': new_files,
                'changed_files': changed_files,
                'deleted_files': deleted_files,
                'duration': duration,
                'timestamp': timezone.now().isoformat()
            }
            
        except Exception as e:
            duration = (timezone.now() - start_time).total_seconds()
            
            # Log failure
            log_data = BackupLogData(
                auth_user=username,
                source_dir=source_dir,
                backup_type=backup_type,
                backup_status="failed",
                backup_duration=duration,
                files_changes={}
            )
            
            self._log_backup_to_database(log_data)
            
            print(f"\n{'='*50}")
            print("Backup Failed!")
            print(f"{'='*50}")
            print(f"Error: {e}")
            print(f"Duration: {duration:.2f} seconds")
            print(f"{'='*50}\n")
            
            return None
    
    @transaction.atomic
    def restore_backup(self, backup_id: int, restore_path: str = None, 
                      username: str = "system") -> Optional[Dict]:
        """
        Restore from a backup
        
        Args:
            backup_id: ID of the backup to restore
            restore_path: Where to restore (defaults to original path)
            username: Username performing the restore
        
        Returns:
            Dict with restore details or None if failed
        """
        start_time = timezone.now()
        
        try:
            backup = BackupRecord.objects.get(id=backup_id, is_active=True)
            
            if restore_path is None:
                restore_path = backup.original_path
            
            os.makedirs(restore_path, exist_ok=True)
            
            restored_files = []
            failed_files = []
            
            for root, dirs, files in os.walk(backup.backup_path):
                relative_root = os.path.relpath(root, backup.backup_path)
                
                for file in files:
                    src_file = os.path.join(root, file)
                    
                    if relative_root == ".":
                        rel_path = file
                    else:
                        rel_path = os.path.join(relative_root, file).replace("\\", "/")
                    
                    dest_file = os.path.join(restore_path, rel_path)
                    
                    try:
                        os.makedirs(os.path.dirname(dest_file), exist_ok=True)

                        shutil.copy2(src_file, dest_file)
                        restored_files.append(rel_path)
                        
                    except Exception as e:
                        failed_files.append({
                            'file': rel_path,
                            'error': str(e)
                        })
            
            # Update backup record
            backup.restored = True
            backup.restore_count += 1
            backup.save()
            
            duration = (timezone.now() - start_time).total_seconds()
            
            FIMLog.objects.create(
                log_type='restore',
                level='info' if not failed_files else 'warning',
                message=f"Restore completed for backup {backup_id}",
                username=username,
                details={
                    'backup_id': backup_id,
                    'original_path': backup.original_path,
                    'restore_path': restore_path,
                    'restored_files': len(restored_files),
                    'failed_files': len(failed_files),
                    'duration': duration,
                    'timestamp': timezone.now().isoformat()
                }
            )
            
            print(f"\n{'='*50}")
            print("Restore Complete!")
            print(f"{'='*50}")
            print(f"Backup: {backup_id}")
            print(f"Source: {backup.backup_path}")
            print(f"Destination: {restore_path}")
            print(f"Restored files: {len(restored_files)}")
            print(f"Failed files: {len(failed_files)}")
            print(f"Duration: {duration:.2f} seconds")
            print(f"{'='*50}\n")
            
            return {
                'backup_id': backup_id,
                'restore_path': restore_path,
                'restored_files': restored_files,
                'failed_files': failed_files,
                'duration': duration,
                'timestamp': timezone.now().isoformat()
            }
            
        except BackupRecord.DoesNotExist:
            print(f"Backup with ID {backup_id} not found or inactive")
            return None
        except Exception as e:
            duration = (timezone.now() - start_time).total_seconds()
            
            FIMLog.objects.create(
                log_type='restore',
                level='error',
                message=f"Restore failed for backup {backup_id}: {str(e)}",
                username=username,
                details={
                    'backup_id': backup_id,
                    'error': str(e),
                    'duration': duration
                }
            )
            
            print(f"\n{'='*50}")
            print("Restore Failed!")
            print(f"{'='*50}")
            print(f"Error: {e}")
            print(f"Duration: {duration:.2f} seconds")
            print(f"{'='*50}\n")
            
            return None
    
    def list_backups(self, directory_path: str = None) -> List[Dict]:
        """List available backups"""
        try:
            queryset = BackupRecord.objects.filter(is_active=True)
            
            if directory_path:
                queryset = queryset.filter(original_path=directory_path)
            
            backups = []
            for backup in queryset.order_by('-backed_up_at'):
                backups.append({
                    'id': backup.id,
                    'original_path': backup.original_path,
                    'backup_path': backup.backup_path,
                    'backup_type': backup.backup_type,
                    'backed_up_at': backup.backed_up_at,
                    'expires_at': backup.expires_at,
                    'backed_up_by': backup.backed_up_by,
                    'size': backup.size,
                    'restored': backup.restored,
                    'restore_count': backup.restore_count
                })
            
            return backups
            
        except Exception as e:
            print(f"Error listing backups: {e}")
            return []
    
    def cleanup_old_backups(self, days_to_keep: int = 30) -> Dict:
        """Cleanup old backups"""
        try:
            cutoff_date = timezone.now() - timedelta(days=days_to_keep)
            
            old_backups = BackupRecord.objects.filter(
                backed_up_at__lt=cutoff_date,
                restored=True  # Only delete restored backups
            )

            deleted_count = 0
            for backup in old_backups:
                try:
                    if os.path.exists(backup.backup_path):
                        shutil.rmtree(backup.backup_path)
                    
                    # Delete database record
                    backup.delete()
                    deleted_count += 1
                    
                except Exception as e:
                    print(f"Error deleting backup {backup.id}: {e}")
            
            FIMLog.objects.create(
                log_type='system',
                level='info',
                message=f"Cleaned up {deleted_count} old backups",
                details={
                    'cutoff_date': cutoff_date.isoformat(),
                    'deleted_count': deleted_count
                }
            )
            
            return {
                'deleted_count': deleted_count,
                'cutoff_date': cutoff_date.isoformat()
            }
            
        except Exception as e:
            print(f"Error cleaning up old backups: {e}")
            return {'deleted_count': 0, 'error': str(e)}


# Utility function for easy backup creation
def create_backup_task(directory_path: str, username: str, 
                      backup_type: str = 'automatic') -> Optional[Dict]:
    """Convenience function for creating backups"""
    backup = Backup()
    return backup.create_backup(directory_path, username, backup_type)


def restore_backup_task(backup_id: int, restore_path: str = None, 
                       username: str = "system") -> Optional[Dict]:
    """Convenience function for restoring backups"""
    backup = Backup()
    return backup.restore_backup(backup_id, restore_path, username)
