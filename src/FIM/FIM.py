import os
import time
import json
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.utils.backup import Backup
from src.utils.database import DatabaseOperation
from src.FIM.fim_utils import FIM_monitor
from src.config.logging_config import configure_logger


class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, parent, logger, db_session, auth_username):
        super().__init__()
        self.parent = parent
        self.logger = logger
        self.directory_path = None
        self.db_session = db_session
        self.auth_username = auth_username
        self.backup_instance = Backup()
        self.database_instance = DatabaseOperation(db_session)

    def _get_directory_path(self, event_path):
        """Extract monitored directory path from event path"""
        for dir_path in self.parent.current_directories:
            if event_path.startswith(dir_path):
                return dir_path
        return os.path.dirname(event_path)

    def on_created(self, event):
        try:
            _path = event.src_path
            if event.is_directory:
                current_hash = self.parent.fim_instance.calculate_folder_hash(_path if isinstance(_path, str) else str(_path))
                is_file = False
            else:
                current_hash = self.parent.fim_instance.calculate_hash(_path if isinstance(_path, str) else str(_path))
                is_file = True

            self.parent.file_folder_addition(_path, current_hash, is_file, self.logger, self.database_instance)

            if not event.is_directory:
                for monitored_dir in self.parent.current_directories:
                    if str(_path).startswith(monitored_dir):
                        self.backup_instance.create_backup(monitored_dir, self.auth_username)
                        break

        except Exception as e:
            self.logger.error(f"Creation error: {str(e)}")

    def on_modified(self, event):
        try:
            _path = event.src_path

            if event.is_directory:
                current_hash = self.parent.fim_instance.calculate_folder_hash(_path if isinstance(_path, str) else str(_path))
                is_file = False
            else:
                current_hash = self.parent.fim_instance.calculate_hash(_path if isinstance(_path, str) else str(_path))
                is_file = True

            dir_path = str(self._get_directory_path(_path))
            file_path = str(_path)
            original_hash = self.database_instance.get_current_baseline(dir_path).get(file_path, {}).get('hash', '')
            self.parent.file_folder_modification(_path, current_hash, original_hash, is_file, self.logger, self.database_instance)

            if not event.is_directory:
                for monitored_dir in self.parent.current_directories:
                    if str(_path).startswith(monitored_dir):
                        self.backup_instance.create_backup(monitored_dir, self.auth_username)
                        break

        except Exception as e:
            self.logger.error(f"Modification error: {str(e)}")

    def on_deleted(self, event):
        try:
            _path = event.src_path
            if event.is_directory:
                is_file = False
            else:
                is_file = True
            dir_path = str(self._get_directory_path(_path))
            file_path = str(_path)
            original_hash = self.database_instance.get_current_baseline(dir_path).get(file_path, {}).get('hash', '')
            self.parent.file_folder_deletion(_path, original_hash, is_file, self.logger, self.database_instance)
        except Exception as e:
            self.logger.error(f"Deletion error: {str(e)}")


class MonitorChanges:
    def __init__(self):
        self.logs_dir = Path(__file__).resolve().parent.parent / "../logs"
        self.logs_dir.mkdir(exist_ok=True, parents=True)

        # Persistent state
        self.reported_changes = {
            "added": {},
            "modified": {},
            "deleted": {},
        }
        self.current_directories = []
        self.event_handlers = []
        self.current_logger = None
        self.auth_username = None

        # Core Components
        self.observer = Observer()
        self.backup_instance = Backup()
        self.fim_instance = FIM_monitor()
        self.configure_logger = configure_logger()

    def file_folder_addition(self, _path, current_hash, is_file, logger, database_instance):
        change_type = "File" if is_file else "Folder"
        if _path not in self.reported_changes["added"]:
            logger.warning(f"{change_type} is added: {_path}")
            self.reported_changes["added"][_path] = {
                "hash": current_hash,
                "last_modified": self.fim_instance.get_formatted_time(os.path.getmtime(_path))
            }

    def file_folder_modification(self, _path, current_hash, original_hash, is_file, logger, database_instance):
        change_type = "File" if is_file else "Folder"

        if current_hash != original_hash:
            if _path not in self.reported_changes["modified"]:
                logger.error(f"{change_type} modified: {_path}")
                self.reported_changes["modified"][_path] = {
                    "hash": current_hash,
                    "last_modified": self.fim_instance.get_formatted_time(os.path.getmtime(_path))
                }
            else:
                previous_hash = self.reported_changes["modified"][_path].get("hash", original_hash)
                if current_hash != previous_hash:
                    logger.error(f"{change_type} modified again: {_path}")
                    self.reported_changes["modified"][_path] = {
                        "hash": current_hash,
                        "last_modified": self.fim_instance.get_formatted_time(os.path.getmtime(_path))
                    }
        else:
            if _path in self.reported_changes["modified"]:
                del self.reported_changes["modified"][_path]

    def file_folder_deletion(self, _path, original_hash, is_file, logger, database_instance):
        change_type = "File" if is_file else "Folder"

        if _path not in self.reported_changes["deleted"]:
            last_modified = database_instance.get_current_baseline(_path).get('last_modified', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            logger.warning(f"{change_type} deleted: {_path}")
            self.reported_changes["deleted"][_path] = {
                "hash": original_hash,
                "last_modified": last_modified
            }

    def monitor_changes(self, auth_username, directories, excluded_files, db_session):
        """Monitor specified directories for changes using Watchdog."""
        try:
            self.auth_username = auth_username
            self.current_directories = directories
            database_instance = DatabaseOperation(db_session) if db_session else None

            for directory in self.current_directories:
                if not os.path.exists(directory):
                    raise FileNotFoundError(f"Directory {directory} does not exist")
                try:
                    self.backup_instance.create_backup(directory, self.auth_username)
                except Exception as e:
                    print(f"Failed to create backup for {directory}")
                    continue

                baseline = self.fim_instance.tracking_directory(self.auth_username, directory, db_session)
                if database_instance:
                    for path, data in baseline.items():
                        database_instance.record_file_event(
                            directory_path=directory,
                            item_path=path,
                            item_hash=data['hash'],
                            item_type=data['type'],
                            last_modified=data['last_modified'],
                            status='current'
                        )

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
            try:
                while True:
                    time.sleep(1)  # Main thread sleep
            except KeyboardInterrupt:
                print("\nShutdown down...")
                self.observer.stop()
                self.observer.join()
                self.configure_logger.shutdown()
                self._save_reported_changes(db_session)
                print("Shutdown complete.")
        except Exception as e:
            if self.current_logger:
                self.current_logger.error(f"Monitoring error: {e}")
            else:
                self.observer.stop()
                self.observer.join()  # Ensure observer is stopped even on error
                self.configure_logger.shutdown()
                print("Shutdown complete.")

    def _save_reported_changes(self, db_session):
        database_instance = DatabaseOperation(db_session)
        for change_type, changes in self.reported_changes.items():
            for path, data in changes.items():
                directory = os.path.dirname(path)
                database_instance.record_file_event(
                    directory_path=directory,
                    item_path=path,
                    item_hash=data['hash'],
                    item_type=data['type'],
                    last_modified=data['last_modified'],
                    status=change_type
                )

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

                print(f"✅ Reset baseline for {directory}")

            except Exception as e:
                print(f"❌ Failed resetting baseline for {directory}: {str(e)}")

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
