import os
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from src.utils.database import DatabaseOperation
from src.config.logging_config import configure_logger


class FIM_monitor:
    def __init__(self, db_session: Optional[Session] = None):
        self.configure_logger = configure_logger()
        self.logger = None

    def get_formatted_time(self, timestamp: float) -> str:
        """Convert a timestamp to a readable format."""
        return time.strftime(r"%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

    def tracking_directory(self, auth_user, directory: str, db_session: Optional[Session] = None) -> Dict[str, Dict[str, Any]]:
        """
        Track the monitored directory and store baseline in the database.
        Returns a dictionary of file/folder metadata.
        """
        current_entries = {}
        self.logger = self.configure_logger._get_or_create_logger(auth_user, directory)

        database_instance = DatabaseOperation(db_session) if db_session else None

        for root, dirs, files in os.walk(directory):
            # ---------------- Handle Folders ----------------
            for folder in dirs:
                folder_path = os.path.join(root, folder)
                folder_hash = None
                last_modified = None

                try:
                    folder_hash = self.calculate_folder_hash(folder_path)
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error calculating folder hash for {folder_path}: {e}")
                    folder_hash = hashlib.sha256(folder_path.encode()).hexdigest()
                
                if not folder_hash:
                    folder_hash = hashlib.sha256(folder_path.encode()).hexdigest()

                try:
                    last_modified = self.get_formatted_time(os.path.getmtime(folder_path))
                except Exception:
                    last_modified = self.get_formatted_time(time.time())

                current_entries[folder_path] = {
                    "type": "folder",
                    "hash": folder_hash,
                    "last_modified": last_modified,
                }

                if database_instance:
                    try:
                        database_instance.record_file_event(
                            directory_path=directory,
                            item_path=folder_path,
                            item_hash=folder_hash,
                            item_type='folder',
                            last_modified=last_modified,
                            status='current'
                        )
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"DB insert failed for folder {folder_path}: {e}")
                        else:
                            print(f"DB insert failed for folder {folder_path}: {e}")

            # ---------------- Handle Files ----------------
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = None
                last_modified = None

                try:
                    file_hash = self.calculate_hash(file_path)
                    if file_hash is None:
                        # fallback for empty or unreadable files
                        file_hash = hashlib.sha256(file_path.encode()).hexdigest()
                except Exception as e:
                    if self.logger:
                        self.logger.error(f"Error calculating file hash for {file_path}: {e}")
                    file_hash = hashlib.sha256(file_path.encode()).hexdigest()

                try:
                    last_modified = self.get_formatted_time(os.path.getmtime(file_path))
                except Exception:
                    last_modified = self.get_formatted_time(time.time())

                current_entries[file_path] = {
                    "type": "file",
                    "hash": file_hash,
                    "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                    "last_modified": last_modified,
                }

                if database_instance:
                    try:
                        database_instance.record_file_event(
                            directory_path=directory,
                            item_path=file_path,
                            item_hash=file_hash,
                            item_type='file',
                            last_modified=last_modified,
                            status='current'
                        )
                    except Exception as e:
                        if self.logger:
                            self.logger.error(f"DB insert failed for file {file_path}: {e}")
                        else:
                            print(f"DB insert failed for file {file_path}: {e}")
                        print(f"DB insert failed for file {file_path}: {e}")

        return current_entries

    # ---------------- Hash Functions ----------------

    def calculate_hash(self, file_path: str) -> Optional[str]:
        """Calculate the SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(4096):
                    sha256.update(chunk)
            sha256.update(os.path.basename(file_path).encode())
            return sha256.hexdigest()
        except (IsADirectoryError, FileNotFoundError, PermissionError) as e:
            if self.logger:
                self.logger.error(f"Error calculating hash for {file_path}: {str(e)}")
            else:
                print(f"Error calculating hash for {file_path}: {str(e)}")
            return None

    def calculate_folder_hash(self, folder_path: str) -> str:
        """Calculate the SHA-256 hash of a folder including subfolders and files."""
        sha256 = hashlib.sha256()
        folder = Path(folder_path)
        sha256.update(folder.name.encode())

        try:
            entries = sorted(folder.iterdir(), key=lambda x: x.name)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Cannot iterate folder {folder_path}: {e}")
            entries = []

        for entry in entries:
            sha256.update(entry.name.encode())
            if entry.is_dir():
                subfolder_hash = self.calculate_folder_hash(str(entry))
                sha256.update(subfolder_hash.encode())
            elif entry.is_file():
                file_hash = self.calculate_hash(str(entry))
                if file_hash:
                    sha256.update(file_hash.encode())

        return sha256.hexdigest()
