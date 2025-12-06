from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from typing import Dict, List, Tuple, cast

from src.api.database.connection import FimSessionLocal
from src.api.models.fim_models import Directory, FileMetadata


class DatabaseOperation:
    """Handles all database interactions using SQLAlchemy ORM."""

    def __init__(self, db:Session):
        self.db:Session = db

    def _commit(self):
        """Commit the transaction safely."""
        try:
            self.db.commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            raise RuntimeError(f"Database commit failed: {e}")

    # ------------------ Directory Operations ------------------

    def get_or_create_directory(self, directory_path: str) -> int:
        """Get or create a directory record, return its ID."""
        try:
            directory = self.db.query(Directory).filter_by(path=directory_path).first()
            if not directory:
                directory = Directory(path=directory_path)
                self.db.add(directory)
                self._commit()
            return cast(int, directory.id)
        except SQLAlchemyError as e:
            self.db.rollback()
            raise RuntimeError(f"Error in get_or_create_directory: {e}")

    def get_all_monitored_directories(self) -> List[str]:
        """Return a list of all monitored directory paths."""
        try:
            directories = self.db.query(Directory.path).all()
            return [d[0] for d in directories]
        except SQLAlchemyError as e:
            raise RuntimeError(f"Error fetching monitored directories: {e}")

    def delete_directory_records(self, directory_path: str):
        """Completely delete a directory and its related file metadata."""
        try:
            directory = self.db.query(Directory).filter_by(path=directory_path).first()
            if directory:
                self.db.delete(directory)
                self._commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            raise RuntimeError(f"Error deleting directory: {e}")

    # ------------------ File Metadata Operations ------------------

    def record_file_event(
        self,
        directory_path: str,
        item_path: str,
        item_hash: str,
        item_type: str,
        last_modified: str,
        status: str,
    ):
        """Insert or update a file event."""
        try:
            dir_id = self.get_or_create_directory(directory_path)
            file_entry = (
                self.db.query(FileMetadata)
                .filter_by(directory_id=dir_id, item_path=item_path)
                .first()
            )

            if file_entry:
                file_entry.hash = item_hash  # type: ignore[assignment]
                file_entry.last_modified = last_modified  # type:ignore[assignment]
                file_entry.status = status  # type: ignore[assignment]
            else:
                new_entry = FileMetadata(
                    directory_id=dir_id,
                    item_path=item_path,
                    item_type=item_type,
                    hash=item_hash,  # type: ignore[arg-type]
                    last_modified=last_modified,
                    status=status  # type: ignore[arg-type]
                )
                self.db.add(new_entry)

            self._commit()

        except SQLAlchemyError as e:
            self.db.rollback()
            raise RuntimeError(f"Error recording file event: {e}")

    def get_current_baseline(self, directory_path: str) -> Dict[str, dict]:
        """Fetch baseline (current) files for a directory."""
        try:
            result = (
                self.db.query(FileMetadata.item_path, FileMetadata.hash, FileMetadata.last_modified)
                .join(Directory)
                .filter(Directory.path == directory_path, FileMetadata.status == "current")
                .all()
            )

            return {
                row[0]: {"hash": row[1], "last_modified": row[2]}
                for row in result
            }
        except SQLAlchemyError as e:
            raise RuntimeError(f"Error fetching current baseline: {e}")

    def get_file_history(self, file_path: str, limit: int = 10) -> List[Tuple]:
        """Fetch file modification history."""
        try:
            result = (
                self.db.query(
                    Directory.path,
                    FileMetadata.hash,
                    FileMetadata.last_modified,
                    FileMetadata.status,
                    FileMetadata.detected_at,
                )
                .join(Directory)
                .filter(FileMetadata.item_path == file_path)
                .order_by(FileMetadata.detected_at.desc())
                .limit(limit)
                .all()
            )
            # convert Sequence[Row[Any]] to List[Tuple] to match the annotated return type
            return [tuple(row) for row in result]
        except SQLAlchemyError as e:
            raise RuntimeError(f"Error fetching file history: {e}")

    def update_file_hash(
        self, file_path: str, new_hash: str, last_modified: str, status: str = "modified"
    ):
        """Update hash and status for a file."""
        try:
            file_entry = self.db.query(FileMetadata).filter_by(item_path=file_path).first()
            if file_entry:
                file_entry.hash = new_hash  # type:ignore[assignment]
                file_entry.last_modified = last_modified  # type:ignore[assignment]
                file_entry.status = status  # type: ignore[assignment]
                self._commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            raise RuntimeError(f"Error updating file hash: {e}")

    def delete_file_record(self, file_path: str):
        """Mark file as deleted."""
        try:
            file_entry = self.db.query(FileMetadata).filter_by(item_path=file_path).first()
            if file_entry:
                file_entry.status = "deleted"  # type: ignore[assignment]
                file_entry.detected_at = datetime.utcnow()  # type:ignore[assignment]
                self._commit()
        except SQLAlchemyError as e:
            self.db.rollback()
            raise RuntimeError(f"Error deleting file record: {e}")

    def get_recent_changes(self, hours: int = 24) -> List[Tuple]:
        """Fetch recent file changes."""
        try:
            from sqlalchemy import text
            query = text(f"""
                SELECT d.path, f.item_path, f.status, f.detected_at
                FROM file_metadata f
                JOIN directories d ON f.directory_id = d.id
                WHERE f.detected_at >= NOW() - INTERVAL {hours} HOUR
                ORDER BY f.detected_at DESC
            """)
            result = self.db.execute(query).fetchall()
            # convert Sequence[Row[Any]] to List[Tuple] for the annotated return type
            return [tuple(row) for row in result]
        except SQLAlchemyError as e:
            raise RuntimeError(f"Error fetching recent changes: {e}")
