"""
Utility functions for environment settings
"""
import os
from pathlib import Path
from dotenv import load_dotenv


def load_environment(env_name=None):
    """
    Load environment variables from .env file
    
    Args:
        env_name: Name of environment (dev, prod, test)
    
    Returns:
        Dict of environment variables
    """
    env_name = env_name or os.getenv('ENVIRONMENT', 'development')
    
    # Determine which .env file to load
    env_files = {
        'development': '.env.dev',
        'production': '.env.prod',
        'test': '.env.test',
        'staging': '.env.staging',
    }
    
    env_file = env_files.get(env_name, '.env.dev')
    env_path = Path(__file__).parent.parent / env_file
    
    if env_path.exists():
        load_dotenv(env_path)
        print(f"Loaded environment from: {env_file}")
    else:
        # Try .env.local as fallback
        local_env = Path(__file__).parent.parent / '.env.local'
        if local_env.exists():
            load_dotenv(local_env)
            print(f"Loaded environment from: .env.local")
        else:
            print(f"Warning: No environment file found for {env_name}")
    
    return dict(os.environ)


def get_database_url(db_type='default'):
    """
    Get database URL from environment variables
    
    Args:
        db_type: 'default' or 'auth'
    
    Returns:
        Database URL string
    """
    if db_type == 'auth':
        engine = os.getenv('AUTH_DB_ENGINE', 'mysql')
        user = os.getenv('AUTH_DB_USER', '')
        password = os.getenv('AUTH_DB_PASSWORD', '')
        host = os.getenv('AUTH_DB_HOST', 'localhost')
        port = os.getenv('AUTH_DB_PORT', '3306')
        name = os.getenv('AUTH_DB_NAME', '')
    else:
        engine = os.getenv('DB_ENGINE', 'mysql')
        user = os.getenv('DB_USER', '')
        password = os.getenv('DB_PASSWORD', '')
        host = os.getenv('DB_HOST', 'localhost')
        port = os.getenv('DB_PORT', '3306')
        name = os.getenv('DB_NAME', '')
    
    # Convert Django engine to SQLAlchemy driver
    if 'mysql' in engine:
        driver = 'pymysql'
        engine = 'mysql'
    elif 'postgresql' in engine:
        driver = 'psycopg2'
        engine = 'postgresql'
    else:
        driver = ''
    
    if driver:
        url = f"{engine}+{driver}://{user}:{password}@{host}:{port}/{name}"
    else:
        url = f"{engine}://{user}:{password}@{host}:{port}/{name}"
    
    return url


def is_development():
    """Check if running in development environment"""
    return os.getenv('ENVIRONMENT', 'development') == 'development'


def is_production():
    """Check if running in production environment"""
    return os.getenv('ENVIRONMENT', 'development') == 'production'


def get_fim_settings():
    """Get FIM-specific settings"""
    from django.conf import settings
    return getattr(settings, 'FIM_SETTINGS', {})
