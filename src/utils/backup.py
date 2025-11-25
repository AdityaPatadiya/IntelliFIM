import os
import shutil
import hashlib
import json
from datetime import datetime

from src.utils.timestamp import timezone
from src.FIM.fim_utils import FIM_monitor


class BackupLogData:
    """Simple class to hold backup log data"""
    def __init__(self, auth_user, source_dir, backup_type, backup_status, backup_duration, files_changes):
        self.auth_user = auth_user
        self.source_dir = source_dir
        self.backup_type = backup_type
        self.backup_status = backup_status
        self.backup_duration = backup_duration
        self.files_changes = files_changes


class Backup:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"current_dir: {current_dir}")
        self.backup_root = os.path.join(current_dir, "../../../FIM_Backup/backup")
        self.meta_file_path = os.path.join(current_dir, "../../../FIM_Backup/backup_metadata.json")  # where all the files hash and information will be stored.
        self.backup_log_path = os.path.join(current_dir, "../../../FIM_Backup/Backup_logs.json")  # where all the backup logs will be stored.

        self.fim_monitor = FIM_monitor()  # fim_utils class for hash calculation

        # create directories or files if not exists
        os.makedirs(self.backup_root, exist_ok=True)
        os.makedirs(os.path.dirname(self.meta_file_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.backup_log_path), exist_ok=True)

        self.metadata = self.load_metadata()

    def load_metadata(self):
        """Load backup metadata from file"""
        try:
            with open(self.meta_file_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def save_metadata(self):
        """Save updated metadata"""
    # this will direct write the new metadata which leads to first erase the old once or the one who never changed needs to fix
        try:
            with open(self.meta_file_path, "w") as f:
                json.dump(self.metadata, f, indent=4)
        except Exception as e:
            print(f"Error saving metadata: {e}")

    def compute_hash(self, folder_path):
        """Compute SHA-256 hash of a file"""
        return self.fim_monitor.calculate_folder_hash(folder_path)

    def log_backup_session(self, current_log_data):
        """Create a timestamped parent backup directory"""
        try:
            if os.path.exists(self.backup_log_path):
                try:
                    with open(self.backup_log_path, "r") as file:
                        existing_data = json.load(file)
                except (json.JSONDecodeError, FileNotFoundError):
                    existing_data = []
            else:
                existing_data = []

            ts_result = timezone()
            timestamp_str = ts_result[0] if isinstance(ts_result, (list, tuple)) and len(ts_result) > 0 else str(datetime.now())
            timezone_str = str(ts_result[1]) if isinstance(ts_result, (list,tuple)) and len(ts_result) > 1 else "Unknown"

            backup_entry = {
                "timestamp": timestamp_str,
                "timezone": timezone_str,
                "user": current_log_data.auth_user,
                "directory": current_log_data.source_dir,
                "backup_type": current_log_data.backup_type,
                "status": current_log_data.backup_status,
                "duration_seconds": current_log_data.backup_duration,
                "file_changes": current_log_data.files_changes
            }

            existing_data.append(backup_entry)

            with open(self.backup_log_path, "w") as file:
                json.dump(existing_data, file, indent=4)
        except Exception as e:
            print(f"Error logging backup session: {e}")

    def create_backup(self, source_dir, auth_username=None):
        """Perform incremental backup: only new or changed files."""
        start_time = datetime.now()

        if not os.path.exists(source_dir):
            print(f"Source directory {source_dir} does not exist.")
            return None
        
        try:
            source_dir = os.path.abspath(source_dir)
            dir_name = os.path.basename(os.path.normpath(source_dir))
            backup_path = os.path.join(self.backup_root, dir_name)
            os.makedirs(backup_path, exist_ok=True)

            changed_files = []
            deleted_files = []

            if source_dir not in self.metadata:
                self.metadata[source_dir] = {}

            current_dir_metadata = self.metadata[source_dir]
            new_metadata = {}

            for root, _, files in os.walk(source_dir):
                relative_root = os.path.relpath(root, source_dir)

                if relative_root == ".":
                    relative_root = ""

                for file in files:
                    src_file = os.path.join(root, file)

                    if relative_root:
                        rel_path = os.path.join(relative_root, file).replace("\\", "/")
                    else:
                        rel_path = file
                    dest_file = os.path.join(backup_path, rel_path)

                    current_hash = self.compute_hash(src_file)
                    if current_hash is None:
                        continue

                    print(f"Current hash: {current_hash}")

                    prev_hash = current_dir_metadata.get(rel_path, {}).get("hash")
                    print(f"Previous hash: {prev_hash}")

                    if current_hash != prev_hash:
                        os.makedirs(os.path.dirname(dest_file), exist_ok=True)
                        shutil.copy2(src_file, dest_file)
                        changed_files.append(rel_path)

                    file_stat = os.stat(src_file)
                    new_metadata[rel_path] = {
                        "hash": current_hash,
                        "last_modified": datetime.fromtimestamp(file_stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "size": file_stat.st_size,
                        "backup_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

            for old_files in list(self.metadata.keys()):
                if old_files not in new_metadata:
                    deleted_files.append(old_files)

            self.metadata = new_metadata
            self.save_metadata()

            duration = (datetime.now() - start_time).total_seconds()
            log_data = BackupLogData(
                auth_user=auth_username or "unknown",
                source_dir=source_dir,
                backup_type="incremental",
                backup_status="success",
                backup_duration=duration,
                files_changes={
                    "changed": changed_files,
                    "deleted": deleted_files
                }
            )
            self.log_backup_session(log_data)

            print("\n=== Incremental Backup Complete ===")
            print(f"Backup location: {backup_path}")
            print(f"Changed/New files: {len(changed_files)}")
            print(f"Deleted files: {len(deleted_files)}")
            print(f"Duration: {duration:.2f} seconds\n")

            return {
                "backup_path": backup_path,
                "changed_files": changed_files,
                "deleted_files": deleted_files
            }

        except Exception as e:
            log_data = BackupLogData(
                auth_user=auth_username or "unknown",
                source_dir=source_dir,
                backup_type="incremental",
                backup_status="failed",
                backup_duration=(datetime.now() - start_time).total_seconds(),
                files_changes={}
            )
            self.log_backup_session(log_data)

            print(f"backup failed: {e}")
            return None
