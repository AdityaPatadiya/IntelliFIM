"""
Handles database connections for both authentication (auth_db)
and File Integrity Monitoring (fim_db) databases using SQLAlchemy ORM.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import QueuePool
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

# Fetch database URLs
AUTH_DATABASE_URL = os.getenv("AUTH_DATABASE_URL")
FIM_DATABASE_URL = os.getenv("FIM_DATABASE_URL")

# --- Validate environment variables ---
if not AUTH_DATABASE_URL:
    raise RuntimeError("❌ Missing AUTH_DATABASE_URL in .env file")

if not FIM_DATABASE_URL:
    raise RuntimeError("❌ Missing FIM_DATABASE_URL in .env file")

# --- MySQL Connection Options ---
# Common connection options for MySQL to handle timeouts and connection issues
mysql_connection_options = {
    "poolclass": QueuePool,
    "pool_size": 10,
    "max_overflow": 20,
    "pool_pre_ping": True,  # Enable connection health checks
    "pool_recycle": 3600,   # Recycle connections after 1 hour
    "echo": False,          # Set to True for debugging SQL queries
    "connect_args": {
        "connect_timeout": 10,
    }
}

# --- Create SQLAlchemy engines with MySQL optimizations ---
auth_engine = create_engine(AUTH_DATABASE_URL, **mysql_connection_options)
fim_engine = create_engine(FIM_DATABASE_URL, **mysql_connection_options)

# --- Define separate Base classes for ORM models ---
AuthBase = declarative_base()
FimBase = declarative_base()

# --- Create SessionLocal factories ---
AuthSessionLocal = sessionmaker(bind=auth_engine, autoflush=False, autocommit=False)
FimSessionLocal = sessionmaker(bind=fim_engine, autoflush=False, autocommit=False)

# --- Dependency functions for FastAPI ---
def get_auth_db():
    """Yields a session connected to the authentication database."""
    db = AuthSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_fim_db():
    """Yields a session connected to the FIM database."""
    db = FimSessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Test connection function (optional) ---
def test_connections():
    """Test database connections on startup"""
    try:
        with auth_engine.connect() as conn:
            print("✅ Authentication database connection successful")
        with fim_engine.connect() as conn:
            print("✅ FIM database connection successful")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        raise
