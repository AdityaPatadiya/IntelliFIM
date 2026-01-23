"""
Celery tasks for File Integrity Monitoring
"""
from celery import shared_task, Task
from celery.utils.log import get_task_logger
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache
import os
import json
from datetime import datetime, timedelta
from pathlib import Path
import traceback
import threading
from typing import List, Dict, Any

from .models import (
    Directory, FileMetadata, FIMLog, BackupRecord,
    ExclusionPattern
)
from .utils.django_logger import fim_logger, log_change, log_backup
from .utils.logging_filters import set_current_user, clear_current_user

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
        
        # Log to database using Django logger
        fim_logger.log_to_database(
            log_type='system',
            level='critical',
            message=error_msg,
            details={'task_id': task_id, 'traceback': traceback.format_exc()}
        )
        
        # Clean up cache
        cache_key = f"task_{task_id}"
        cache.delete(cache_key)


try:
    from .core.FIM import MonitorChanges
    from .core.django_adapters import DjangoDatabaseAdapter
    fim_monitor = MonitorChanges()
    db_adapter = DjangoDatabaseAdapter()
except ImportError as e:
    logger.warning(f"Could not import FIM modules: {e}")
    
    class MockMonitorChanges:
        def __init__(self):
            self.current_directories = []
            self.observer = None
        
        def monitor_changes(self, username, directories, excluded_files=None):
            logger.info(f"Mock: Would start monitoring {directories}")
            self.current_directories = directories
            set_current_user(username)
        
        def stop_monitoring(self):
            logger.info("Mock: Stopping monitoring")
            self.current_directories = []
        
        def reset_baseline(self, username, directories):
            logger.info(f"Mock: Resetting baseline for {directories}")
            set_current_user(username)
    
    fim_monitor = MockMonitorChanges()
    db_adapter = None


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
        set_current_user(username)
        
        cache.set(cache_key, {
            'status': 'initializing',
            'progress': 0,
            'message': 'Validating directories...',
            'started_at': timezone.now().isoformat(),
            'directories': directories
        }, timeout=3600)
        
        invalid_dirs = []
        for directory in directories:
            if not os.path.exists(directory):
                invalid_dirs.append(directory)
        
        if invalid_dirs:
            raise ValueError(f"Directories do not exist: {invalid_dirs}")
        
        active_dirs = fim_monitor.current_directories if hasattr(fim_monitor, 'current_directories') else []
        overlapping = set(directories) & set(active_dirs)
        if overlapping:
            raise ValueError(f"Directories already monitored: {list(overlapping)}")
        
        cache.set(cache_key, {
            'status': 'processing',
            'progress': 30,
            'message': 'Creating directory records...'
        }, timeout=3600)
        
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
        
        success_dirs = []
        failed_dirs = []
        
        try:
            def run_monitoring():
                try:
                    set_current_user(username)
                    fim_monitor.monitor_changes(
                        username,
                        directories,
                        excluded_files or []
                    )
                except Exception as e:
                    fim_logger.log_to_database(
                        log_type='system',
                        level='error',
                        message=f"Monitoring thread error: {str(e)}",
                        username=username,
                        details={'error': str(e), 'traceback': traceback.format_exc()}
                    )
                    logger.error(f"Monitoring error: {e}")
            
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
            fim_logger.log_to_database(
                log_type='system',
                level='error',
                message=f"Failed to start monitoring: {str(e)}",
                username=username,
                details={'error': str(e), 'traceback': traceback.format_exc()}
            )
            logger.error(f"Failed to start monitoring: {e}")
        
        for directory in success_dirs:
            fim_logger.log_to_database(
                log_type='scan',
                level='info',
                message=f"Started monitoring directory: {directory}",
                username=username,
                directory=directory
            )
        
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
        }, timeout=7200)
        
        fim_logger.log_to_database(
            log_type='system',
            level='info',
            message=f"FIM monitoring task completed: {len(success_dirs)} directories started successfully",
            username=username,
            details={
                'success_dirs': success_dirs,
                'failed_dirs': failed_dirs,
                'task_id': task_id
            }
        )
        
        return {
            'task_id': task_id,
            'status': 'completed',
            'success_dirs': success_dirs,
            'failed_dirs': failed_dirs,
            'created_dirs': created_dirs,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"FIM monitoring task failed: {str(e)}",
            username=username,
            details={
                'error': str(e),
                'traceback': traceback.format_exc(),
                'task_id': task_id
            }
        )
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
        set_current_user(username)
        
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
                if (hasattr(fim_monitor, "current_directories") and 
                    directory in fim_monitor.current_directories):
                    fim_monitor.current_directories.remove(directory)
                    
                    if remove_from_db:
                        Directory.objects.filter(path=directory).delete()
                    else:
                        Directory.objects.filter(path=directory).update(
                            is_active=False,
                            last_scan=timezone.now()
                        )
                    
                    stopped_dirs.append(directory)
                    
                    fim_logger.log_to_database(
                        log_type='scan',
                        level='info',
                        message=f"Stopped monitoring directory: {directory}",
                        username=username,
                        directory=directory
                    )
                else:
                    error_dirs.append({'directory': directory, 'error': 'Not actively monitored'})
                    fim_logger.log_to_database(
                        log_type='system',
                        level='warning',
                        message=f"Directory not actively monitored: {directory}",
                        username=username,
                        directory=directory
                    )
                    
            except Exception as e:
                error_dirs.append({'directory': directory, 'error': str(e)})
                fim_logger.log_to_database(
                    log_type='system',
                    level='error',
                    message=f"Error stopping directory {directory}: {str(e)}",
                    username=username,
                    directory=directory,
                    details={'error': str(e)}
                )
                logger.error(f"Error stopping {directory}: {e}")
        
        if (hasattr(fim_monitor, "current_directories") and 
            len(fim_monitor.current_directories) == 0):
            try:
                fim_monitor.stop_monitoring()
                fim_logger.log_to_database(
                    log_type='system',
                    level='info',
                    message="FIM monitor stopped completely",
                    username=username
                )
            except Exception as e:
                fim_logger.log_to_database(
                    log_type='system',
                    level='error',
                    message=f"Error stopping observer: {str(e)}",
                    username=username,
                    details={'error': str(e)}
                )
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

        fim_logger.log_to_database(
            log_type='system',
            level='info',
            message=f"Stop monitoring task completed: {len(stopped_dirs)} directories stopped",
            username=username,
            details={
                'stopped_dirs': stopped_dirs,
                'error_dirs': error_dirs,
                'task_id': task_id
            }
        )
        
        return {
            'task_id': task_id,
            'stopped_dirs': stopped_dirs,
            'error_dirs': error_dirs,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Stop monitoring task failed: {str(e)}",
            username=username,
            details={
                'error': str(e),
                'traceback': traceback.format_exc(),
                'task_id': task_id
            }
        )
        logger.error(f"Stop monitoring task failed: {e}")
        
        cache.set(cache_key, {
            'status': 'failed',
            'message': str(e),
            'traceback': traceback.format_exc()
        }, timeout=3600)
        
        raise


@shared_task(base=BaseTaskWithRetry, bind=True, queue='fim_monitor')
def reset_baseline_task(self, username: str, directories: List[str]) -> Dict[str, Any]:
    """
    Reset baseline for directories using your existing FIM logic
    """
    task_id = self.request.id
    cache_key = f"baseline_task_{task_id}"
    
    try:
        set_current_user(username)
        
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
                
                fim_monitor.reset_baseline(username, [directory])

                dir_obj = Directory.objects.get(path=directory)
                dir_obj.last_scan = timezone.now()
                dir_obj.save()

                baseline_count = FileMetadata.objects.filter(
                    directory=dir_obj,
                    status='current'
                ).count()

                results.append({
                    'directory': directory,
                    'success': True,
                    'baseline_count': baseline_count
                })

                fim_logger.log_to_database(
                    log_type='system',
                    level='info',
                    message=f"Baseline reset for {directory}: {baseline_count} files in baseline",
                    username=username,
                    directory=directory,
                    details={'baseline_count': baseline_count}
                )
                
            except Exception as e:
                results.append({
                    'directory': directory,
                    'success': False,
                    'error': str(e)
                })
                fim_logger.log_to_database(
                    log_type='system',
                    level='error',
                    message=f"Baseline reset failed for {directory}: {str(e)}",
                    username=username,
                    directory=directory,
                    details={'error': str(e)}
                )
                logger.error(f"Baseline reset failed for {directory}: {e}")
        
        cache.set(cache_key, {
            'status': 'completed',
            'progress': 100,
            'message': 'Baseline reset completed',
            'completed_at': timezone.now().isoformat(),
            'results': results
        }, timeout=7200)
        
        successful = sum(1 for r in results if r['success'])
        fim_logger.log_to_database(
            log_type='system',
            level='info',
            message=f"Baseline reset task completed: {successful}/{total_dirs} successful",
            username=username,
            details={'results': results, 'task_id': task_id}
        )
        
        return {
            'task_id': task_id,
            'results': results,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Baseline reset task failed: {str(e)}",
            username=username,
            details={
                'error': str(e),
                'traceback': traceback.format_exc(),
                'task_id': task_id
            }
        )
        logger.error(f"Baseline reset task failed: {e}")
        
        cache.set(cache_key, {
            'status': 'failed',
            'message': str(e),
            'traceback': traceback.format_exc()
        }, timeout=3600)
        
        raise


@shared_task(base=BaseTaskWithRetry, queue='default')
def calculate_baseline_for_directory(directory_path: str, username: str = 'system') -> Dict[str, Any]:
    """
    Calculate baseline for a single directory using your existing FIM logic
    """
    try:
        set_current_user(username)
        
        dir_obj = Directory.objects.get(path=directory_path)
        dir_obj.last_scan = timezone.now()
        dir_obj.save()
        
        baseline_count = FileMetadata.objects.filter(
            directory=dir_obj,
            status='current'
        ).count()
        
        fim_logger.log_to_database(
            log_type='scan',
            level='info',
            message=f"Baseline calculated for {directory_path}: {baseline_count} files",
            username=username,
            directory=directory_path,
            details={'file_count': baseline_count}
        )
        
        return {
            'directory': directory_path,
            'baseline_count': baseline_count,
            'success': True
        }
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Baseline calculation failed for {directory_path}: {str(e)}",
            username=username,
            directory=directory_path,
            details={'error': str(e)}
        )
        logger.error(f"Baseline calculation failed for {directory_path}: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='default')
def cleanup_old_data(days_to_keep: int = 30) -> Dict[str, Any]:
    """
    Cleanup old FIM data
    """
    try:
        cutoff_date = timezone.now() - timedelta(days=days_to_keep)
        
        old_changes = FileMetadata.objects.filter(
            status__in=['added', 'modified', 'deleted'],
            detected_at__lt=cutoff_date
        )
        
        old_count = old_changes.count()
        
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
        
        deleted_count, _ = old_changes.delete()
        
        old_logs = FIMLog.objects.filter(timestamp__lt=cutoff_date)
        logs_deleted = old_logs.count()
        old_logs.delete()
        
        expired_backups = BackupRecord.objects.filter(
            expires_at__lt=timezone.now(),
            restored=True
        )
        backups_deleted = expired_backups.count()
        expired_backups.delete()
        
        fim_logger.log_to_database(
            log_type='system',
            level='info',
            message=f"Data cleanup completed: {deleted_count} old changes, {logs_deleted} old logs, {backups_deleted} expired backups removed",
            username='system',
            details={
                'changes_deleted': deleted_count,
                'logs_deleted': logs_deleted,
                'backups_deleted': backups_deleted,
                'cutoff_date': cutoff_date.isoformat()
            }
        )
        
        return {
            'changes_deleted': deleted_count,
            'logs_deleted': logs_deleted,
            'backups_deleted': backups_deleted,
            'cutoff_date': cutoff_date.isoformat()
        }
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Data cleanup failed: {str(e)}",
            username='system',
            details={'error': str(e)}
        )
        logger.error(f"Data cleanup failed: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='default')
def check_monitoring_health() -> Dict[str, Any]:
    """
    Check health of all monitoring tasks
    """
    try:
        set_current_user('system')
        
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
        
        if health_report['issues']:
            fim_logger.log_to_database(
                log_type='system',
                level='warning',
                message=f"Monitoring health check found {len(health_report['issues'])} issues",
                username='system',
                details=health_report
            )
        else:
            fim_logger.log_to_database(
                log_type='system',
                level='info',
                message="Monitoring health check passed",
                username='system',
                details=health_report
            )
        
        return health_report
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Health check failed: {str(e)}",
            username='system',
            details={'error': str(e)}
        )
        logger.error(f"Health check failed: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='default')
def export_fim_report(start_date: str, end_date: str, 
                      report_type: str = 'changes') -> Dict[str, Any]:
    """
    Export FIM report for given date range
    """
    try:
        set_current_user('system')
        
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
            
            # Log report generation
            fim_logger.log_to_database(
                log_type='report',
                level='info',
                message=f"FIM report generated: {report_path}",
                username='system',
                details={
                    'report_path': report_path,
                    'total_changes': len(report_data),
                    'period': {'start': start_date, 'end': end_date}
                }
            )
            
            return {
                'success': True,
                'report_path': report_path,
                'total_changes': len(report_data),
                'period': {'start': start_date, 'end': end_date}
            }
        
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Invalid report type requested: {report_type}",
            username='system',
            details={'report_type': report_type}
        )
        return {'success': False, 'error': 'Invalid report type'}
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Report export failed: {str(e)}",
            username='system',
            details={'error': str(e)}
        )
        logger.error(f"Report export failed: {e}")
        raise


@shared_task(queue='default')
def notify_on_changes(change_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send notifications about detected changes
    """
    try:
        username = change_data.get('username', 'system')
        set_current_user(username)
        
        fim_logger.log_to_database(
            log_type='alert',
            level='info',
            message=f"Change detected: {change_data.get('file_path')} ({change_data.get('change_type')})",
            username=username,
            details=change_data
        )
        
        if 'file_path' in change_data and 'change_type' in change_data:
            log_change(
                change_data.get('change_type'),
                change_data.get('file_path'),
                username,
                change_data
            )
        
        return {'notified': True, 'change_id': change_data.get('change_id')}
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Notification failed: {str(e)}",
            username=change_data.get('username', 'system'),
            details={'error': str(e), 'change_data': change_data}
        )
        logger.error(f"Notification failed: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='fim_scans')
def perform_directory_scan(directory_path: str, username: str = 'system') -> Dict[str, Any]:
    """
    Perform a simple directory scan using Django ORM
    """
    try:
        set_current_user(username)
        
        dir_obj = Directory.objects.get(path=directory_path)
        
        baseline_files = FileMetadata.objects.filter(
            directory=dir_obj,
            status='current'
        )
        
        baseline_count = baseline_files.count()

        dir_obj.last_scan = timezone.now()
        dir_obj.save()
        
        fim_logger.log_to_database(
            log_type='scan',
            level='info',
            message=f"Directory scan completed for {directory_path}: {baseline_count} files",
            username=username,
            directory=dir_obj,
            details={'file_count': baseline_count}
        )
        
        return {
            'directory': directory_path,
            'success': True,
            'file_count': baseline_count,
            'scan_time': timezone.now().isoformat()
        }
        
    except Exception as e:
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Directory scan failed for {directory_path}: {str(e)}",
            username=username,
            directory=directory_path,
            details={'error': str(e)}
        )
        logger.error(f"Directory scan failed for {directory_path}: {e}")
        raise


@shared_task(base=BaseTaskWithRetry, queue='fim_backup')
def simple_restore_task(username: str, path_to_restore: str) -> Dict[str, Any]:
    """
    Simple restore task placeholder
    """
    try:
        set_current_user(username)
        
        fim_logger.log_to_database(
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
        fim_logger.log_to_database(
            log_type='system',
            level='error',
            message=f"Restore task failed: {str(e)}",
            username=username,
            details={'error': str(e), 'path': path_to_restore}
        )
        logger.error(f"Restore task failed: {e}")
        raise
