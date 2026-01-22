"""
Django-integrated File Integrity Monitoring core
"""
import os
import time
import json
import asyncio
import traceback
import threading
from pathlib import Path
from datetime import datetime
import concurrent.futures
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from django.utils import timezone
from django.core.cache import cache
from django.db import transaction

from .django_adapters import DjangoDatabaseAdapter
from fim_utils import FIMMonitor
from .fim_shared import event_queue, get_fim_loop
from ..utils.backup import Backup
from ..utils.thread_pool import thread_pool

try:
    from fim.models import FileMetadata, Directory, FIMLog
except ImportError:
    pass


class EventDeduplicator:
    """Prevents duplicate events within a short time window"""
    def __init__(self, window_seconds=1.0):
        self.window_seconds = window_seconds
        self.recent_events = {}
        self.lock = threading.Lock()

    def should_process(self, event_type, file_path):
        """Check if we should process this event (not a duplicate)"""
        current_time = time.time()
        event_key = f"{event_type}_{file_path}"

        with self.lock:
            to_remove = []
            for key, (event_time, _) in self.recent_events.items():
                if current_time - event_time > self.window_seconds:
                    to_remove.append(key)

            for key in to_remove:
                self.recent_events.pop(key, None)

            if event_key in self.recent_events:
                return False            
            self.recent_events[event_key] = (current_time, file_path)
            return True


async def push_event(change_type, file_path, details):
    if isinstance(details, dict):
        for key, value in details.items():
            if hasattr(value, 'isoformat'):
                details[key] = value.isoformat()
            elif isinstance(value, datetime):
                details[key] = value.strftime("%Y-%m-%d %H:%M:%S")
    
    event_data = {
        "type": change_type,
        "path": file_path,
        "details": details
    }

    await event_queue.put(event_data)


class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, parent, username):
        super().__init__()
        self.parent = parent
        self.username = username
        self.directory_path = None
        self.is_active = True
        
        self.database_adapter = DjangoDatabaseAdapter()

        self.fim_monitor = FIMMonitor(username=username)

        self.hash_cache = {}
        self.cache_timeout = 5.0

    def _is_valid_event(self, event_path):
        """Check if this event should be processed."""
        if not self.is_active:
            return False

        if not hasattr(self.parent, "current_directories"):
            return False
        
        for dir_path in self.parent.current_directories:
            if event_path.startswith(dir_path):
                return True
        return False

    def _get_directory_path(self, event_path):
        """Extract monitored directory path from event path"""
        for dir_path in self.parent.current_directories:
            if event_path.startswith(dir_path):
                return dir_path
        return os.path.dirname(event_path)

    def _get_timestamp_safe(self, path):
        """Safely get modification timestamp with error handling."""
        try: 
            return self.fim_monitor.get_formatted_time(os.path.getmtime(path))
        except (FileNotFoundError, OSError):
            return timezone.now().strftime("%Y-%m-%d %H:%M:%S")

    def _get_cached_hash(self, path, is_folder=False):
        """Get cached hash if available and not expired."""
        current_time = time.time()
        if path in self.hash_cache:
            cached_time, cached_hash = self.hash_cache[path]
            if current_time - cached_time < self.cache_timeout:
                return cached_hash
        return None

    def _calculate_hash_async(self, path, is_folder=False):
        """Calculate hash in thread pool and cache result."""
        cached_hash = self._get_cached_hash(path, is_folder)
        if cached_hash is not None:
            return cached_hash
        
        if is_folder:
            future = thread_pool.submit(
                self.fim_monitor.calculate_folder_hash,
                str(path)
            )
        else:
            future = thread_pool.submit(
                self.fim_monitor.calculate_hash,
                str(path)
            )

        try:
            current_hash = future.result(timeout=10.0)  # 10 second timeout
            self.hash_cache[path] = (time.time(), current_hash)
            return current_hash
        except concurrent.futures.TimeoutError:
            self._log_error(f"Hashing timeout for: {path}")
            return "TIMEOUT_ERROR"
        except Exception as e:
            self._log_error(f"Hashing error for {path}: {str(e)}")
            return "HASH_ERROR"
    
    def _log_error(self, message):
        """Log error using Django models"""
        try:
            FIMLog.objects.create(
                log_type='system',
                level='error',
                message=message,
                username=self.username
            )
        except Exception:
            print(f"ERROR: {message}")

    def _should_backup(self, path):
        """Determine if backup should be created for this change."""
        backup_key = f"backup_{path}"
        current_time = time.time()

        if hasattr(self, '_last_backup_time'):
            if backup_key in self._last_backup_time:
                last_time = self._last_backup_time[backup_key]
                # Only backup if 5 seconds has passed.
                if current_time - last_time < 5.0:
                    return False
        
        if not hasattr(self, '_last_backup_time'):
            self._last_backup_time = {}
        self._last_backup_time[backup_key] = current_time
        return True

    def _process_addition(self, _path, current_hash, is_file):
        """Process addition with Django ORM."""
        try:
            dir_path = os.path.dirname(_path)
            directory, _ = Directory.objects.get_or_create(
                path=dir_path,
                defaults={'is_active': False}
            )
            
            FileMetadata.objects.create(
                directory=directory,
                item_path=os.path.basename(_path),
                item_type='file' if is_file else 'directory',
                hash=current_hash,
                last_modified=timezone.now(),
                status='added',
                detected_at=timezone.now()
            )
            
            FIMLog.objects.create(
                log_type='change',
                level='info',
                message=f"File added: {_path}",
                directory=directory,
                username=self.username
            )
            
        except Exception as e:
            self._log_error(f"Addition processing error for {_path}: {str(e)}")

    def on_created(self, event):
        try:
            if not self._is_valid_event(event.src_path):
                return
            _path = event.src_path
            is_file = not event.is_directory

            if not self.parent.event_deduplicator.should_process("created", _path):
                return

            if event.is_directory:
                current_hash = self._calculate_hash_async(_path, is_folder=True)
            else:
                current_hash = self._calculate_hash_async(_path, is_folder=False)

            thread_pool.submit(
                self._process_addition,
                _path, current_hash, is_file
            )

            if not event.is_directory and self._should_backup(_path):
                for monitored_dir in self.parent.current_directories:
                    if str(_path).startswith(monitored_dir):
                        thread_pool.submit(
                            self.parent.backup_instance.create_backup,
                            monitored_dir, self.username
                        )
                        break

        except Exception as e:
            self._log_error(f"Creation error: {str(e)}")

    def _process_modification(self, _path, current_hash, is_file):
        """Process modification with Django ORM"""
        try:
            # Get directory and file metadata
            dir_path = os.path.dirname(_path)
            file_name = os.path.basename(_path)
            
            directory = Directory.objects.filter(path=dir_path).first()
            if not directory:
                directory, _ = Directory.objects.get_or_create(
                    path=dir_path,
                    defaults={'is_active': False}
                )
            
            # Update or create file metadata
            file_meta, created = FileMetadata.objects.update_or_create(
                directory=directory,
                item_path=file_name,
                defaults={
                    'item_type': 'file' if is_file else 'directory',
                    'hash': current_hash,
                    'last_modified': timezone.now(),
                    'status': 'modified' if not created else 'current',
                    'detected_at': timezone.now()
                }
            )
            
            # Log to FIMLog
            FIMLog.objects.create(
                log_type='change',
                level='warning',
                message=f"File modified: {_path}",
                directory=directory,
                username=self.username
            )
            
        except Exception as e:
            self._log_error(f"Modification processing error for {_path}: {str(e)}")

    def on_modified(self, event):
        try:
            if not self._is_valid_event(event.src_path):
                return
            _path = event.src_path
            is_file = not event.is_directory

            if not self.parent.event_deduplicator.should_process("modified", _path):
                return

            if event.is_directory:
                current_hash = self._calculate_hash_async(_path, is_folder=True)
            else:
                current_hash = self._calculate_hash_async(_path, is_folder=False)

            thread_pool.submit(
                self._process_modification,
                _path, current_hash, is_file
            )

            if not event.is_directory and self._should_backup(_path):
                for monitored_dir in self.parent.current_directories:
                    if str(_path).startswith(monitored_dir):
                        thread_pool.submit(
                            self.parent.backup_instance.create_backup,
                            monitored_dir, self.username
                        )
                        break

        except Exception as e:
            self._log_error(f"Modification error: {str(e)}")

    def _process_deletion(self, _path, is_file):
        """Process deletion with Django ORM."""
        try:
            dir_path = os.path.dirname(_path)
            file_name = os.path.basename(_path)
            
            directory = Directory.objects.filter(path=dir_path).first()
            if directory:
                # Mark as deleted in database
                FileMetadata.objects.filter(
                    directory=directory,
                    item_path=file_name
                ).update(status='deleted', detected_at=timezone.now())
                
                # Log to FIMLog
                FIMLog.objects.create(
                    log_type='change',
                    level='warning',
                    message=f"File deleted: {_path}",
                    directory=directory,
                    username=self.username
                )
            
        except Exception as e:
            self._log_error(f"Deletion processing error for {_path}: {str(e)}")

    def on_deleted(self, event):
        try:
            if not self._is_valid_event(event.src_path):
                return  
            _path = event.src_path
            is_file = not event.is_directory

            if not self.parent.event_deduplicator.should_process("deleted", _path):
                return

            thread_pool.submit(
                self._process_deletion,
                _path, is_file
            )
        except Exception as e:
            self._log_error(f"Deletion error: {str(e)}")


class MonitorChanges:
    def __init__(self):
        # Use Django's BASE_DIR for logs
        from django.conf import settings
        self.logs_dir = Path(settings.BASE_DIR) / "logs"
        self.logs_dir.mkdir(exist_ok=True, parents=True)

        self._stop_flag = threading.Event()
        self.observer_thread = None

        # Core Components
        self.observer = None
        self.backup_instance = Backup()
        self.fim_monitor = FIMMonitor()
        self.event_deduplicator = EventDeduplicator(window_seconds=0.5)

        self.reset_state()

    def reset_state(self):
        """Reset all state variables"""
        self.current_directories = []
        self.event_handlers = []
        self.auth_username = None

        if hasattr(self, '_stop_flag'):
            self._stop_flag.clear()

    def _get_timestamp_safe(self, path):
        """Safely get modification timestamp with error handling."""
        try: 
            return self.fim_monitor.get_formatted_time(os.path.getmtime(path))
        except (FileNotFoundError, OSError):
            return timezone.now().strftime("%Y-%m-%d %H:%M:%S")

    @transaction.atomic
    def monitor_changes(self, auth_username, directories, excluded_files=None):
        """Monitor specified directories for changes using Watchdog."""
        try:
            self.stop_monitoring()
            self.reset_state()

            self.auth_username = auth_username
            self.current_directories = directories
            
            if excluded_files is None:
                excluded_files = []

            self.observer = Observer()

            futures = []
            for directory in self.current_directories:
                if not os.path.exists(directory):
                    raise FileNotFoundError(f"Directory {directory} does not exist")

                future = thread_pool.submit(
                    self._initialize_directory_baseline,
                    directory, auth_username
                )
                futures.append(future)

            for future in futures:
                try:
                    future.result(timeout=30.0)
                except Exception as e:
                    print(f"Warning: Failed to initialize baseline: {str(e)}") 

            for directory in self.current_directories:
                if directory in excluded_files:
                    continue

                event_handler = FIMEventHandler(self, auth_username)
                event_handler.directory_path = directory
                self.observer.schedule(event_handler, directory, recursive=True)
                self.event_handlers.append(event_handler)
                
                FIMLog.objects.create(
                    log_type='system',
                    level='info',
                    message=f"Starting monitoring for {directory}",
                    username=auth_username
                )

            self.observer.start()
            print(f"FIM monitoring started for {len(self.current_directories)} directories")

            # Start observer thread
            self.observer_thread = threading.Thread(
                target=self._run_observer,
                daemon=True,
                name=f"FIM-Observer-{auth_username}"
            )
            self.observer_thread.start()

        except Exception as e:
            FIMLog.objects.create(
                log_type='system',
                level='error',
                message=f"Monitoring error: {str(e)}",
                username=auth_username
            )
            self.stop_monitoring()
            raise

    def stop_monitoring(self):
        """Stop monitoring completely."""
        self._stop_flag.set()
        
        # Stop observer if exists
        if hasattr(self, 'observer') and self.observer:
            try:
                if self.observer.is_alive():
                    self.observer.stop()
                    self.observer.join(timeout=5)
            except Exception as e:
                print(f"Error stopping observer: {e}")
            finally:
                self.observer = None
        
        # Wait for observer thread
        if self.observer_thread and self.observer_thread.is_alive():
            try:
                self.observer_thread.join(timeout=3)
            except Exception:
                pass
        
        # Log stop
        if self.auth_username:
            FIMLog.objects.create(
                log_type='system',
                level='info',
                message=f"Monitoring stopped",
                username=self.auth_username
            )

    def _initialize_directory_baseline(self, directory, auth_username):
        """Initialize baseline for a directory (run in thread pool)."""
        try:
            baseline = self.fim_monitor.track_directory(directory, auth_username)
            
            self.backup_instance.create_backup(directory, auth_username)
            
            print(f"Baseline initialized for {directory}")
        except Exception as e:
            print(f"Failed to initialize baseline for {directory}: {str(e)}")
            traceback.print_exc()

    def _run_observer(self):
        """Run observer in a separate thread."""
        try:
            while not self._stop_flag.is_set() and self.observer and self.observer.is_alive():
                time.sleep(1)

        except KeyboardInterrupt:
            print("\nShutting down FIM monitor...")
        except Exception as e:
            print(f"Observer thread error: {str(e)}")
        finally:
            self._cleanup()

    def _cleanup(self):
        """Cleanup resources."""
        self.stop_monitoring()

    def reset_baseline(self, auth_username: str, directories: list[str]):
        """Reset baseline for specified directories using Django ORM."""
        for directory in directories:
            try:
                dir_path = Path(directory)
                if not dir_path.exists():
                    print(f"Directory not found: {directory}")
                    continue

                dir_obj, created = Directory.objects.get_or_create(
                    path=str(dir_path),
                    defaults={'is_active': False, 'recursive': True}
                )
                
                FileMetadata.objects.filter(directory=dir_obj).delete()
                
                self.fim_monitor.track_directory(directory, auth_username)
                
                print(f"Reset baseline for {directory}")
                
                # Log reset
                FIMLog.objects.create(
                    log_type='system',
                    level='info',
                    message=f"Baseline reset for {directory}",
                    directory=dir_obj,
                    username=auth_username
                )

            except Exception as e:
                print(f"Failed resetting baseline for {directory}: {str(e)}")

    def view_baseline(self, directory=None):
        """View baseline data from Django database."""
        try:
            if directory:
                # Get baseline for specific directory
                baseline_files = FileMetadata.objects.filter(
                    directory__path=directory,
                    status='current'
                ).select_related('directory')
                
                baseline = {}
                for file_meta in baseline_files:
                    baseline[file_meta.item_path] = {
                        'hash': file_meta.hash,
                        'last_modified': file_meta.last_modified,
                        'type': file_meta.item_type
                    }
                
                print(f"\nBaseline for {directory}:")
                print(json.dumps(baseline, indent=4, default=str))
            else:
                # Get all directories with baseline
                directories = Directory.objects.all()
                for dir_obj in directories:
                    baseline_files = FileMetadata.objects.filter(
                        directory=dir_obj,
                        status='current'
                    ).count()
                    
                    print(f"{dir_obj.path}: {baseline_files} files in baseline")

        except Exception as e:
            print(f"Error viewing baseline: {str(e)}")

    def view_logs(self, directory=None):
        """View logs from Django database or log files."""
        try:
            if directory:
                dir_obj = Directory.objects.filter(path=directory).first()
                if dir_obj:
                    logs = FIMLog.objects.filter(
                        directory=dir_obj
                    ).order_by('-timestamp')[:100]
                    
                    for log in logs:
                        print(f"{log.timestamp} [{log.level}] {log.message}")
                else:
                    print(f"No directory found: {directory}")
            else:
                logs = FIMLog.objects.all().order_by('-timestamp')[:50]
                for log in logs:
                    dir_name = log.directory.path if log.directory else "System"
                    print(f"{log.timestamp} [{log.level}] {dir_name}: {log.message}")
                    
        except Exception as e:
            print(f"Log viewing error: {str(e)}")
