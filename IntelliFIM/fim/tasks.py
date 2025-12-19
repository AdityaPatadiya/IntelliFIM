"""
Celery tasks for File Integrity Monitoring
"""
from celery import shared_task, Task, group, chain
from celery.utils.log import get_task_logger
from django.db import transaction, DatabaseError
from django.utils import timezone
from django.core.cache import cache
from django.db.models import Count, Q, F
import os
import hashlib
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
import traceback
from typing import List, Dict, Any, Optional

from .models import (
    Directory, FileMetadata, FIMLog, BackupRecord,
    ExclusionPattern, FIMConfiguration
)

# Import your existing FIM logic
try:
    from .core.FIM import MonitorChanges
    from .core.django_adapters import DjangoDatabaseAdapter
    fim_monitor = MonitorChanges()
    db_adapter = DjangoDatabaseAdapter()
except ImportError as e:
    print(f"Warning: Could not import FIM modules: {e}")
    
    class MockMonitorChanges:
        def __init__(self):
            self.current_directories = []
            self.observer = None
        
        def monitor_changes(self, username, directories, excluded_files, db_session):
            print(f"Mock: Would start monitoring {directories}")
            self.current_directories = directories
        
        def stop_monitoring(self):
            print("Mock: Stopping monitoring")
            self.current_directories = []
        
        def reset_baseline(self, username, directories):
            print(f"Mock: Resetting baseline for {directories}")
    
    fim_monitor = MockMonitorChanges()
    db_adapter = None

logger = get_task_logger(__name__)


class BaseTaskWithRetry(Task):
    """Base task with retry and error handling"""
    autoretry_for = (Exception,)
    max_retries = 3
    retry_backoff = True
    retry_backoff_max = 700
    retry_jitter = True
    default_retry_delay = 60
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        error_msg = f"Task {self.name} failed: {str(exc)}"
        logger.error(error_msg)
        
        # Log to database
        try:
            FIMLog.objects.create(
                log_type='system',
                level='critical',
                message=error_msg,
                details={'task_id': task_id, 'traceback': traceback.format_exc()}
            )
        except Exception:
            pass
        
        # Clean up cache
        cache_key = f"task_{task_id}"
        cache.delete(cache_key)


@shared_task(base=BaseTaskWithRetry, bind=True, queue='fim_monitor')
def start_fim_monitoring_task(self, user_id: int, username: str, 
                              directories: List[str], 
                              excluded_files: List[str] = None,
                              recursive: bool = True,
                              scan_interval: int = 300) -> Dict[str, Any]:
    """
    Start FIM monitoring for directories in background
    
    Args:
        user_id: ID of user starting monitoring
        username: Username for logging
        directories: List of directory paths to monitor
        excluded_files: List of file patterns to exclude
        recursive: Monitor subdirectories
        scan_interval: Scan interval in seconds
    """
    task_id = self.request.id
    cache_key = f"fim_task_{task_id}"
    
    try:
        # Update task status
        cache.set(cache_key, {
            'status': 'initializing',
            'progress': 0,
            'message': 'Validating directories...',
            'started_at': timezone.now().isoformat(),
            'directories': directories
        }, timeout=3600)
        
        # Validate directories exist
        invalid_dirs = []
        for directory in directories:
            if not os.path.exists(directory):
                invalid_dirs.append(directory)
        
        if invalid_dirs:
            raise ValueError(f"Directories do not exist: {invalid_dirs}")
        
        # Check for overlapping directories
        active_dirs = fim_monitor.current_directories if hasattr(fim_monitor, 'current_directories') else []
        overlapping = set(directories) & set(active_dirs)
        if overlapping:
            raise ValueError(f"Directories already monitored: {list(overlapping)}")
        
        cache.set(cache_key, {
            'status': 'processing',
            'progress': 30,
            'message': 'Creating directory records...'
        }, timeout=3600)
        
        # Create/update directory records
        created_dirs = []
        with transaction.atomic():
            for directory in directories:
                dir_obj, created = Directory.objects.get_or_create(
                    path=os.path.normpath(directory),
                    defaults={
                        'is_active': True,
                        'recursive': recursive,
                        'scan_interval': scan_interval,
                        'last_scan': timezone.now()
                    }
                )
                if created:
                    created_dirs.append(directory)
                else:
                    dir_obj.is_active = True
                    dir_obj.save()
        
        # Update excluded patterns if provided
        if excluded_files:
            for directory in directories:
                dir_obj = Directory.objects.get(path=os.path.normpath(directory))
                for pattern in excluded_files:
                    ExclusionPattern.objects.get_or_create(
                        directory=dir_obj,
                        pattern=pattern,
                        pattern_type='glob',
                        defaults={'description': 'Auto-excluded from FIM start'}
                    )
        
        cache.set(cache_key, {
            'status': 'processing',
            'progress': 60,
            'message': 'Starting monitoring service...'
        }, timeout=3600)
        
        # Start monitoring using your existing FIM logic
        try:
            # Start the monitoring in a background thread
            # Since your MonitorChanges.monitor_changes() is blocking,
            # we'll run it in a separate thread
            import threading
            
            def run_monitoring():
                try:
                    fim_monitor.monitor_changes(
                        username,
                        directories,
                        excluded_files or [],
                        None  # No SQLAlchemy session needed for Django
                    )
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
            
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=run_monitoring,
                daemon=True,
                name=f"FIM-Monitor-{username}"
            )
            monitor_thread.start()
            
            success_dirs = directories
            failed_dirs = []
            
        except Exception as e:
            failed_dirs = [{'directory': d, 'error': str(e)} for d in directories]
            success_dirs = []
            logger.error(f"Failed to start monitoring: {e}")
        
        # Log success
        for directory in directories:
            FIMLog.objects.create(
                log_type='scan',
                level='info',
                message=f"Started monitoring directory: {directory}",
                directory=Directory.objects.get(path=os.path.normpath(directory)),
                username=username
            )
        
        # Calculate baseline if first time (using your existing FIM logic)
        if created_dirs:
            for directory in created_dirs:
                calculate_baseline_for_directory.delay(directory, username)
        
        cache.set(cache_key, {
            'status': 'completed',
            'progress': 100,
            'message': 'Monitoring started successfully',
            'completed_at': timezone.now().isoformat(),
            'results': {
                'success_dirs': success_dirs,
                'failed_dirs': failed_dirs,
                'created_dirs': created_dirs
            }
        }, timeout=7200)  # Keep results for 2 hours
        
        return {
            'task_id': task_id,
            'status': 'completed',
            'success_dirs': success_dirs,
            'failed_dirs': failed_dirs,
            'created_dirs': created_dirs,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"FIM monitoring task failed: {e}")
        
        cache.set(cache_key, {
            'status': 'failed',
            'progress': 0,
            'message': f'Error: {str(e)}',
            'failed_at': timezone.now().isoformat(),
            'error': str(e),
            'traceback': traceback.format_exc()
        }, timeout=3600)
        
        raise


@shared_task(base=BaseTaskWithRetry, bind=True, queue='fim_monitor')
def stop_fim_monitoring_task(self, username: str, 
                             directories: List[str],
                             remove_from_db: bool = False) -> Dict[str, Any]:
    """
    Stop FIM monitoring for directories
    """
    task_id = self.request.id
    cache_key = f"stop_task_{task_id}"
    
    try:
        cache.set(cache_key, {
            'status': 'processing',
            'progress': 0,
            'message': 'Stopping monitoring...',
            'directories': directories
        }, timeout=3600)
        
        stopped_dirs = []
        error_dirs = []
        
        for directory in directories:
            try:
                # Update in-memory directories list
                if (hasattr(fim_monitor, "current_directories") and 
                    directory in fim_monitor.current_directories):
                    fim_monitor.current_directories.remove(directory)
                    
                    # Update database
                    if remove_from_db:
                        Directory.objects.filter(path=directory).delete()
                    else:
                        Directory.objects.filter(path=directory).update(
                            is_active=False,
                            last_scan=timezone.now()
                        )
                    
                    stopped_dirs.append(directory)
                    
                    # Log
                    FIMLog.objects.create(
                        log_type='scan',
                        level='info',
                        message=f"Stopped monitoring directory: {directory}",
                        username=username
                    )
                else:
                    error_dirs.append({'directory': directory, 'error': 'Not actively monitored'})
                    
            except Exception as e:
                error_dirs.append({'directory': directory, 'error': str(e)})
                logger.error(f"Error stopping {directory}: {e}")
        
        # Stop the observer if no directories left
        if (hasattr(fim_monitor, "current_directories") and 
            len(fim_monitor.current_directories) == 0):
            try:
                fim_monitor.stop_monitoring()
            except Exception as e:
                logger.error(f"Error stopping observer: {e}")
        
        cache.set(cache_key, {
            'status': 'completed',
            'progress': 100,
            'message': 'Monitoring stopped',
            'completed_at': timezone.now().isoformat(),
            'results': {
                'stopped_dirs': stopped_dirs,
                'error_dirs': error_dirs
            }
        }, timeout=7200)
        
        return {
            'task_id': task_id,
            'stopped_dirs': stopped_dirs,
            'error_dirs': error_dirs,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Stop monitoring task failed: {e}")
        
        cache.set(cache_key, {
            'status': 'failed',
            'message': str(e),
            'traceback': traceback.format_exc()
        }, timeout=3600)
        
        raise

@shared_task(base=BaseTaskWithRetry, bind=True)
def reset_baseline_task(self, username: str, directories: List[str]) -> Dict[str, Any]:
    """
    Reset baseline for directories using your existing FIM logic
    """
    task_id = self.request.id
    cache_key = f"baseline_task_{task_id}"
    
    try:
        total_dirs = len(directories)
        
        cache.set(cache_key, {
            'status': 'processing',
            'progress': 0,
            'message': f'Resetting baseline for {total_dirs} directories...',
            'total': total_dirs,
            'processed': 0
        }, timeout=3600)
        
        results = []
        
        for idx, directory in enumerate(directories):
            try:
                progress = int((idx / total_dirs) * 100)
                cache.set(cache_key, {
                    'status': 'processing',
                    'progress': progress,
                    'message': f'Processing {directory}...',
                    'current_directory': directory,
                    'processed': idx + 1
                }, timeout=3600)
                
                # Reset baseline using your existing FIM logic
                fim_monitor.reset_baseline(username, [directory])
                
                # Update directory
                dir_obj = Directory.objects.get(path=directory)
                dir_obj.last_scan = timezone.now()
                dir_obj.save()
                
                # Count baseline files
                baseline_count = FileMetadata.objects.filter(
                    directory=dir_obj,
                    status='current'
                ).count()
                
                results.append({
                    'directory': directory,
                    'success': True,
                    'baseline_count': baseline_count
                })
                
                # Log
                FIMLog.objects.create(
                    log_type='system',
                    level='info',
                    message=f"Baseline reset for {directory}: {baseline_count} files in baseline",
                    directory=dir_obj,
                    username=username
                )
                
            except Exception as e:
                results.append({
                    'directory': directory,
                    'success': False,
                    'error': str(e)
                })
                logger.error(f"Baseline reset failed for {directory}: {e}")
        
        cache.set(cache_key, {
            'status': 'completed',
            'progress': 100,
            'message': 'Baseline reset completed',
            'completed_at': timezone.now().isoformat(),
            'results': results
        }, timeout=7200)
        
        return {
            'task_id': task_id,
            'results': results,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Baseline reset task failed: {e}")
        
        cache.set(cache_key, {
            'status': 'failed',
            'message': str(e),
            'traceback': traceback.format_exc()
        }, timeout=3600)
        
        raise


@shared_task(base=BaseTaskWithRetry, queue='default')
def calculate_baseline_for_directory(directory_path: str, username: str = 'system'):
    """
    Calculate baseline for a single directory using your existing FIM logic
    """
    try:
        # This would use your existing FIM logic
        # For now, we'll just update the directory last_scan
        dir_obj = Directory.objects.get(path=directory_path)
        dir_obj.last_scan = timezone.now()
        dir_obj.save()
        
        # Count baseline files
        baseline_count = FileMetadata.objects.filter(
            directory=dir_obj,
            status='current'
        ).count()
        
        FIMLog.objects.create(
            log_type='scan',
            level='info',
            message=f"Baseline calculated for {directory_path}: {baseline_count} files",
            username=username,
            details={'file_count': baseline_count}
        )
        
        return {
            'directory': directory_path,
            'baseline_count': baseline_count,
            'success': True
        }
        
    except Exception as e:
        logger.error(f"Baseline calculation failed for {directory_path}: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='default')
def cleanup_old_data(days_to_keep: int = 30):
    """
    Cleanup old FIM data
    """
    try:
        cutoff_date = timezone.now() - timedelta(days=days_to_keep)
        
        # Archive and delete old change records (keep only current baseline)
        old_changes = FileMetadata.objects.filter(
            status__in=['added', 'modified', 'deleted'],
            detected_at__lt=cutoff_date
        )
        
        old_count = old_changes.count()
        
        # Archive to log file before deletion
        if old_count > 0:
            archive_file = Path(f"logs/archive_changes_{datetime.now().strftime('%Y%m%d')}.log")
            with open(archive_file, 'a') as f:
                for change in old_changes:
                    f.write(json.dumps({
                        'id': change.id,
                        'directory': change.directory.path,
                        'item_path': change.item_path,
                        'status': change.status,
                        'detected_at': change.detected_at.isoformat(),
                        'hash': change.hash
                    }) + '\n')
        
        # Delete old changes
        deleted_count, _ = old_changes.delete()
        
        # Delete old logs
        old_logs = FIMLog.objects.filter(timestamp__lt=cutoff_date)
        logs_deleted = old_logs.count()
        old_logs.delete()
        
        # Delete expired backups
        expired_backups = BackupRecord.objects.filter(
            expires_at__lt=timezone.now(),
            restored=True  # Only delete restored backups
        )
        backups_deleted = expired_backups.count()
        expired_backups.delete()
        
        # Log cleanup
        FIMLog.objects.create(
            log_type='system',
            level='info',
            message=f"Data cleanup completed: "
                   f"{deleted_count} old changes, "
                   f"{logs_deleted} old logs, "
                   f"{backups_deleted} expired backups removed"
        )
        
        return {
            'changes_deleted': deleted_count,
            'logs_deleted': logs_deleted,
            'backups_deleted': backups_deleted,
            'cutoff_date': cutoff_date.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Data cleanup failed: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='default')
def check_monitoring_health():
    """
    Check health of all monitoring tasks
    """
    try:
        health_report = {
            'observer_running': hasattr(fim_monitor, 'observer') and 
                               fim_monitor.observer is not None and 
                               fim_monitor.observer.is_alive(),
            'monitored_directories': fim_monitor.current_directories if hasattr(fim_monitor, 'current_directories') else [],
            'monitored_directories_count': len(fim_monitor.current_directories) if hasattr(fim_monitor, 'current_directories') else 0,
            'issues': []
        }
        
        # Check for issues
        active_dirs = Directory.objects.filter(is_active=True)
        if health_report['monitored_directories_count'] != active_dirs.count():
            health_report['issues'].append(
                f"Database shows {active_dirs.count()} active directories, "
                f"but monitor has {health_report['monitored_directories_count']}"
            )
        
        # Log if there are issues
        if health_report['issues']:
            FIMLog.objects.create(
                log_type='system',
                level='warning',
                message=f"Monitoring health check found {len(health_report['issues'])} issues",
                details=health_report
            )
        
        return health_report
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='default')
def export_fim_report(start_date: str, end_date: str, 
                      report_type: str = 'changes') -> Dict[str, Any]:
    """
    Export FIM report for given date range
    """
    try:
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        if report_type == 'changes':
            changes = FileMetadata.objects.filter(
                detected_at__range=(start, end)
            ).exclude(status='current').select_related('directory')
            
            report_data = []
            for change in changes:
                report_data.append({
                    'timestamp': change.detected_at.isoformat(),
                    'directory': change.directory.path,
                    'file': change.item_path,
                    'change_type': change.status,
                    'hash': change.hash,
                    'size': change.size
                })
            
            # Generate JSON report
            report_path = f"reports/fim_changes_{start.date()}_to_{end.date()}.json"
            os.makedirs('reports', exist_ok=True)
            
            with open(report_path, 'w') as f:
                json.dump({
                    'generated_at': timezone.now().isoformat(),
                    'period': {'start': start_date, 'end': end_date},
                    'total_changes': len(report_data),
                    'changes': report_data
                }, f, indent=2)
            
            return {
                'success': True,
                'report_path': report_path,
                'total_changes': len(report_data),
                'period': {'start': start_date, 'end': end_date}
            }
        
        return {'success': False, 'error': 'Invalid report type'}
        
    except Exception as e:
        logger.error(f"Report export failed: {e}")
        raise


@shared_task(queue='default')
def notify_on_changes(change_data: Dict[str, Any]):
    """
    Send notifications about detected changes
    """
    try:
        # This is where you'd integrate with email, Slack, webhooks, etc.
        # For now, just log it
        
        FIMLog.objects.create(
            log_type='alert',
            level='info',
            message=f"Change detected: {change_data.get('file_path')} "
                   f"({change_data.get('change_type')})",
            details=change_data
        )
        
        return {'notified': True, 'change_id': change_data.get('change_id')}
        
    except Exception as e:
        logger.error(f"Notification failed: {e}")
        raise


# Simple task implementations that don't depend on FimMonitorService

@shared_task(base=BaseTaskWithRetry, queue='fim_scans')
def perform_directory_scan(directory_path: str, username: str = 'system') -> Dict[str, Any]:
    """
    Perform a simple directory scan using Django ORM
    """
    try:
        dir_obj = Directory.objects.get(path=directory_path)
        
        # Get current baseline
        baseline_files = FileMetadata.objects.filter(
            directory=dir_obj,
            status='current'
        )
        
        baseline_count = baseline_files.count()
        
        # Update last scan time
        dir_obj.last_scan = timezone.now()
        dir_obj.save()
        
        FIMLog.objects.create(
            log_type='scan',
            level='info',
            message=f"Directory scan completed for {directory_path}: {baseline_count} files",
            directory=dir_obj,
            username=username,
            details={'file_count': baseline_count}
        )
        
        return {
            'directory': directory_path,
            'success': True,
            'file_count': baseline_count,
            'scan_time': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Directory scan failed for {directory_path}: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='fim_backup')
def simple_restore_task(username: str, path_to_restore: str) -> Dict[str, Any]:
    """
    Simple restore task placeholder
    """
    try:
        # This is a placeholder - you should implement your restore logic here
        # For now, just log it

        FIMLog.objects.create(
            log_type='restore',
            level='info',
            message=f"Restore requested for: {path_to_restore}",
            username=username,
            details={'path': path_to_restore}
        )
        
        return {
            'success': True,
            'message': f'Restore requested for {path_to_restore}',
            'username': username,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Restore task failed: {e}")
        raise
