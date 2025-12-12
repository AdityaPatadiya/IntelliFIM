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

from src.utils.backup import Backup
from src.utils.database import DatabaseOperation
from src.FIM.fim_utils import FIM_monitor
from src.config.logging_config import configure_logger
from src.FIM.fim_shared import event_queue, get_fim_loop
from src.utils.thread_pool import thread_pool
from src.utils.database_manager import get_thread_local_fim_session, close_thread_local_fim_session


async def push_event(change_type, file_path, details):
    await event_queue.put({
        "type": change_type,
        "path": file_path,
        "details": details
    })


class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, parent, logger, db_session, auth_username):
        super().__init__()
        self.parent = parent
        self.logger = logger
        self.directory_path = None
        self.main_db_session = db_session
        self.auth_username = auth_username
        self.backup_instance = Backup()
        self.is_active = True

        # Cache for hashing results to avoid recomputing
        self.hash_cache = {}
        self.cache_timeout = 5.0  # Cache hash for 5 seconds

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
            return self.parent.fim_instance.get_formatted_time(os.path.getmtime(path))
        except (FileNotFoundError, OSError):
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
                self.parent.fim_instance.calculate_folder_hash,
                str(path)
            )
        else:
            future = thread_pool.submit(
                self.parent.fim_instance.calculate_hash,
                str(path)
            )

        try:
            current_hash = future.result(timeout=10.0)  # 10 second timeout
            # Cache the result
            self.hash_cache[path] = (time.time(), current_hash)
            return current_hash
        except concurrent.futures.TimeoutError:
            self.logger.error(f"Hashing timeout for: {path}")
            return "TIMEOUT_ERROR"
        except Exception as e:
            self.logger.error(f"Hashing error for {path}: {str(e)}")
            return "HASH_ERROR"
    
    def _should_backup(self, path):
        """Determine if backup should be created for this change.
           Don't backup too frequently - only if file hasn't been backed up recently.
        """
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
        """Process addition in thread pool with thread-local session."""
        session = get_thread_local_fim_session()
        try:
            database_instance = DatabaseOperation(session)
            self.parent.file_folder_addition(_path, current_hash, is_file, self.logger, database_instance)
            session.commit()
        except Exception as e:
            session.rollback()
            self.logger.error(f"Addition processing error: {str(e)}")
        finally:
            close_thread_local_fim_session()

    def on_created(self, event):
        try:
            if not self._is_valid_event(event.src_path):
                return
            _path = event.src_path
            is_file = not event.is_directory

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
                            self.backup_instance.create_backup,
                            monitored_dir, self.auth_username
                        )
                        break

        except Exception as e:
            self.logger.error(f"Creation error: {str(e)}")

    def _process_modification(self, _path, current_hash, is_file, dir_path, file_path):
        """Process modification in thread pool with thread-local session"""
        session = get_thread_local_fim_session()
        try:
            database_instance = DatabaseOperation(session)

            original_hash = ""
            try:
                baseline = database_instance.get_current_baseline(dir_path)
                original_hash = baseline.get(file_path, {}).get('hash', '')
            except Exception:
                pass

            self.parent.file_folder_modification(_path, current_hash, original_hash, is_file, self.logger, database_instance)
            session.commit()
        except Exception as e:
            session.rollback()
            self.logger.error(f"Modification processing error: {str(e)}")
        finally:
            close_thread_local_fim_session()

    def on_modified(self, event):
        try:
            if not self._is_valid_event(event.src_path):
                return
            _path = event.src_path
            is_file = not event.is_directory

            if event.is_directory:
                current_hash = self._calculate_hash_async(_path, is_folder=True)
            else:
                current_hash = self._calculate_hash_async(_path, is_folder=False)

            dir_path = str(self._get_directory_path(_path))
            file_path = str(_path)

            thread_pool.submit(
                self._process_modification,
                _path, current_hash, is_file, dir_path, file_path
            )

            if not event.is_directory and self._should_backup(_path):
                for monitored_dir in self.parent.current_directories:
                    if str(_path).startswith(monitored_dir):
                        thread_pool.submit(
                            self.backup_instance.create_backup,
                            monitored_dir, self.auth_username
                        )
                        break

        except Exception as e:
            self.logger.error(f"Modification error: {str(e)}")

    def _process_deletion(self, _path, is_file, dir_path, file_path):
        """Process deletion in therad pool with thread-local session."""
        session = get_thread_local_fim_session()
        try:
            database_instance = DatabaseOperation(session)

            original_hash = ""
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                baseline = database_instance.get_current_baseline(dir_path)
                path_norm = os.path.normpath(file_path)
                original_hash = baseline.get(path_norm, {}).get('hash', '')
                timestamp = baseline.get(path_norm, {}).get('last_modified', timestamp)
            except Exception:
                pass

            self.parent.file_folder_deletion(_path, original_hash, is_file, self.logger, database_instance)
            session.commit()
        except Exception as e:
            session.rollback()
            self.logger.error(f"Deletion processing error: {str(e)}")
        finally:
            close_thread_local_fim_session()

    def on_deleted(self, event):
        try:
            if not self._is_valid_event(event.src_path):
                return  
            _path = event.src_path
            is_file = not event.is_directory
            dir_path = str(self._get_directory_path(_path))
            file_path = str(_path)

            thread_pool.submit(
                self._process_deletion,
                _path, is_file, dir_path, file_path
            )
        except Exception as e:
            self.logger.error(f"Deletion error: {str(e)}")


class MonitorChanges:
    def __init__(self):
        self.logs_dir = Path(__file__).resolve().parent.parent / "../logs"
        self.logs_dir.mkdir(exist_ok=True, parents=True)

        self._stop_flag = threading.Event()
        self.observer_thread = None

        # Core Components
        self.observer = None
        self.backup_instance = Backup()
        self.fim_instance = FIM_monitor()
        self.configure_logger = configure_logger()
        self.parent_thread_pool = thread_pool

        self.reset_state()

    def reset_state(self):
        """Reset all state variable"""
        self.reported_changes = {
            "added": {},
            "modified": {},
            "deleted": {},
        }
        self.current_directories = []
        self.event_handlers = []
        self.current_logger = None
        self.auth_username = None
        self.db_session = None

        if hasattr(self, '_stop_flag'):
            self._stop_flag.clear()

    def file_folder_addition(self, _path, current_hash, is_file, logger, database_instance):
        change_type = "File" if is_file else "Folder"
        timestamp = self._get_timestamp_safe(_path)

        if _path not in self.reported_changes["added"]:
            logger.warning(f"{change_type} is added: {_path}")
            self.reported_changes["added"][_path] = {
                "hash": current_hash,
                "last_modified": timestamp
            }

        asyncio.run_coroutine_threadsafe(
            push_event("added", _path, {
                "hash": current_hash,
                "timestamp": timestamp
            }),
            get_fim_loop()
        )

    def file_folder_modification(self, _path, current_hash, original_hash, is_file, logger, database_instance):
        change_type = "File" if is_file else "Folder"
        timestamp = self._get_timestamp_safe(_path)

        if current_hash != original_hash:
            if _path not in self.reported_changes["modified"]:
                logger.error(f"{change_type} modified: {_path}")
                self.reported_changes["modified"][_path] = {
                    "hash": current_hash,
                    "last_modified": timestamp
                }
            else:
                previous_hash = self.reported_changes["modified"][_path].get("hash", original_hash)
                if current_hash != previous_hash:
                    logger.error(f"{change_type} modified again: {_path}")
                    self.reported_changes["modified"][_path] = {
                        "hash": current_hash,
                        "last_modified": timestamp
                    }
        else:
            if _path in self.reported_changes["modified"]:
                del self.reported_changes["modified"][_path]

        asyncio.run_coroutine_threadsafe(
            push_event("modified", _path, {
                "hash": current_hash,
                "timestamp": timestamp
            }),
            get_fim_loop()
        )

    def file_folder_deletion(self, _path, original_hash, is_file, logger, database_instance):
        change_type = "File" if is_file else "Folder"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if _path not in self.reported_changes["deleted"]:
            logger.warning(f"{change_type} deleted: {_path}")
            self.reported_changes["deleted"][_path] = {
                "hash": original_hash,
                "last_modified": timestamp
            }

        asyncio.run_coroutine_threadsafe(
            push_event("deleted", _path, {
                "timestamp": timestamp
            }),
            get_fim_loop()
        )

    def _get_timestamp_safe(self, path):
        """Safely get modification timestamp with error handling."""
        try: 
            return self.fim_instance.get_formatted_time(os.path.getmtime(path))
        except (FileNotFoundError, OSError):
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def monitor_changes(self, auth_username, directories, excluded_files, db_session):
        """Monitor specified directories for changes using Watchdog."""
        try:
            self.stop_monitoring()
            self.reset_state()

            self.auth_username = auth_username
            self.current_directories = directories
            self.db_session = db_session

            self.observer = Observer()
            database_instance = DatabaseOperation(db_session) if db_session else None

            # initialize baselines in thread pool
            futures = []
            for directory in self.current_directories:
                if not os.path.exists(directory):
                    raise FileNotFoundError(f"Directory {directory} does not exist")

                future = self.parent_thread_pool.submit(
                    self._initialize_directory_baseline,
                    directory, auth_username, db_session, database_instance
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

                logger = self.configure_logger._get_or_create_logger(self.auth_username, directory)
                logger.info(f"Starting monitoring for {directory}")

                event_handler = FIMEventHandler(self, logger, db_session, self.auth_username)
                event_handler.directory_path = directory
                self.observer.schedule(event_handler, directory, recursive=True)
                self.event_handlers.append(event_handler)

            self.observer.start()
            print(f"FIM monitoring started for {len(self.current_directories)} directories")

            self.observer_thread = threading.Thread(
                target=self._run_observer,
                daemon=True,
                name=f"FIM-Observer-{auth_username}"
            )
            self.observer_thread.start()

        except Exception as e:
            if self.current_logger:
                self.current_logger.error(f"Monitoring error: {e}")
            else:
                self.stop_monitoring()
                print(f"Monitoring error: {e}")

    def stop_monitoring(self):
        """Stop monitoring completely."""
        self._stop_flag.set()  # Signal thread to stop
        
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
        
        # Wait for observer thread to finish
        if self.observer_thread and self.observer_thread.is_alive():
            try:
                self.observer_thread.join(timeout=3)
            except Exception:
                pass
        
        # Save any pending changes
        if hasattr(self, 'db_session') and self.db_session:
            self._save_reported_changes(self.db_session)

    def _initialize_directory_baseline(self, directory, auth_username, db_session, database_instance):
        """Initialize baseline for a directory (run in thread pool)."""
        session = get_thread_local_fim_session()
        try:
            thread_database_instance = DatabaseOperation(session)

            self.backup_instance.create_backup(directory, auth_username)
            baseline = self.fim_instance.tracking_directory(auth_username, directory, session)

            baseline_copy = dict(baseline)
            save_count = 0

            for path, data in baseline_copy.items():
                try:
                    thread_database_instance.record_file_event(
                        directory_path=directory,
                        item_path=path,
                        item_hash=data.get('hash', ''),
                        item_type=data.get('type', 'file'),
                        last_modified=data.get('last_modified', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        status='current'
                    )
                    save_count += 1
                except Exception as e:
                    print(f"Warning: could not save {path}: {str(e)}")

            session.commit()
            print(f"Baseline initialized for {directory} ({save_count} items)")
        except Exception as e:
            session.rollback()
            print(f"Failed to initialize baseline for {directory}: {str(e)}")
            traceback.print_exc()
        finally:
            close_thread_local_fim_session()

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
        if hasattr(self, 'db_session') and self.db_session:
            self._save_reported_changes(self.db_session)

    def _save_reported_changes(self, db_session):
        database_instance = DatabaseOperation(db_session)
        for change_type, changes in self.reported_changes.items():
            for path, data in changes.items():
                # Resolve the monitored root directory that contains this path
                monitored_root = None
                try:
                    abs_path = os.path.abspath(path)
                except Exception:
                    abs_path = path

                # Normalize both sides before comparison
                for root in self.current_directories:
                    try:
                        root_abs = os.path.abspath(root)
                    except Exception:
                        root_abs = root

                    # Ensure trailing sep won't break startswith comparisons
                    if not root_abs.endswith(os.sep):
                        root_abs_cmp = root_abs + os.sep
                    else:
                        root_abs_cmp = root_abs

                    if not abs_path.endswith(os.sep):
                        abs_path_cmp = abs_path + os.sep
                    else:
                        abs_path_cmp = abs_path

                    if abs_path_cmp.startswith(root_abs_cmp) or abs_path == root_abs:
                        monitored_root = root_abs
                        break

                # fallback to dirname (should rarely happen)
                if not monitored_root:
                    monitored_root = os.path.dirname(path)

                try:
                    item_type = "file" if os.path.isfile(path) else "folder"
                except Exception:
                    # If filesystem state can't be read (deleted), rely on recorded change type
                    item_type = "file" if change_type == "added" or change_type == "modified" else "folder"

                try:
                    database_instance.record_file_event(
                        directory_path=monitored_root,
                        item_path=path,
                        item_hash=data.get('hash', ''),
                        item_type=item_type,
                        last_modified=data.get('last_modified', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        status=change_type
                    )
                except Exception as e:
                    print(f"Error saving change for {path}: {str(e)}")


    def view_baseline(self, db_session=None):
        """View ALL baselines with datetime serialization support"""
        try:
            if not db_session:
                print("No database session provide.")
                return
            
            database_instance = DatabaseOperation(db_session)
            directories = database_instance.get_all_monitored_directories()

            if not directories:
                print("No baseline data exists in database")
                return

            for directory in directories:
                print(f"\nBaseline for {directory}:")
                baseline = database_instance.get_current_baseline(directory)

                class DateTimeEncoder(json.JSONEncoder):
                    def default(self, o):
                        if isinstance(o, datetime):
                            return o.strftime("%Y-%m-%d %H:%M:%S")
                        return super().default(o)

                print(json.dumps(baseline, indent=4, cls=DateTimeEncoder))

        except Exception as e:
            print(f"Error viewing baseline: {str(e)}")

    def reset_baseline(self, auth_username: str, directories: list[str], db_session=None):
        """Safely reset baseline for specified directories using SQLAlchemy ORM."""
        if not db_session:
            print("No database session provide.")
            return

        database_instance = DatabaseOperation(db_session)
        for directory in directories:
            try:
                dir_path = Path(directory)
                if not dir_path.exists():
                    print(f"Directory not found: {directory}")
                    continue

                database_instance.delete_directory_records(directory)
                self.fim_instance.tracking_directory(auth_username, directory, db_session)

                print(f"Reset baseline for {directory}")

            except Exception as e:
                print(f"Failed resetting baseline for {directory}: {str(e)}")

    def view_logs(self, directory=None):
        """View logs safely with path validation"""
        try:
            if directory:
                norm_dir = Path(directory).resolve()
                if not norm_dir.exists():
                    print(f"Directory {directory} does not exist")
                    return

                log_file = self.logs_dir / f"FIM_{norm_dir.name}.log"
                if log_file.exists():
                    with open(log_file, 'r', encoding='utf-8') as f:
                        print(f.read())
                else:
                    print(f"No logs for {directory}")
            else:
                for log_path in self.logs_dir.glob("FIM_*.log"):
                    print(f"\n=== Logs for {log_path.stem} ===")
                    with open(log_path, 'r', encoding='utf-8') as f:
                        print(f.read())  # Show first 4KB per file [read(4096)]
        except Exception as e:
            print(f"Log viewing error: {str(e)}")
