"""
Database session manager for thread-safe operations.
"""
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from src.api.database.connection import FIM_DATABASE_URL
import threading


class DatabaseSessionManager:
    """Manages thread-local database sessions."""
    
    _instances = {}
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls, database_url):
        """Get a singleton instance for a database URL."""
        with cls._lock:
            if database_url not in cls._instances:
                cls._instances[database_url] = cls(database_url)
            return cls._instances[database_url]

    def __init__(self, database_url):
        self.engine = create_engine(database_url)
        self.SessionLocal = sessionmaker(
            autocommit=False, 
            autoflush=False, 
            bind=self.engine
        )
        self.thread_local = threading.local()

    def get_session(self):
        """Get a thread-local session."""
        if not hasattr(self.thread_local, "session"):
            self.thread_local.session = self.SessionLocal()
        return self.thread_local.session

    def close_session(self):
        """Close the thread-local session."""
        if hasattr(self.thread_local, "session"):
            try:
                self.thread_local.session.close()
            except:
                pass
            delattr(self.thread_local, "session")

    def cleanup(self):
        """Cleanup all sessions."""
        if hasattr(self.thread_local, "session"):
            try:
                self.thread_local.session.close()
            except:
                pass
            delattr(self.thread_local, "session")


# Global instance for FIM database
fim_db_manager = DatabaseSessionManager.get_instance(FIM_DATABASE_URL)


def get_thread_local_fim_session():
    """Get a thread-local FIM database session."""
    return fim_db_manager.get_session()


def close_thread_local_fim_session():
    """Close the thread-local FIM database session."""
    fim_db_manager.close_session()
