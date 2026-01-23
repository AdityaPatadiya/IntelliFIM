"""
Django-integrated logger for FIM
"""
import os
import logging
import re
from pathlib import Path
from django.conf import settings
from django.utils import timezone

from .logging_filters import set_current_user, clear_current_user


class DjangoFIMLogger:
    """Django-native FIM logger"""

    def __init__(self):
        self.loggers = {}
        self.logs_dir = os.path.join(settings.BASE_DIR, 'logs')
        Path(self.logs_dir).mkdir(parents=True, exist_ok=True)

    def _sanitize_basename(self, directory):
        """Sanitize directory name for log filename"""
        basename = os.path.basename(os.path.normpath(directory))
        return re.sub(r'[\\/*?:"<>|]', '_', basename).strip('_')

    def get_logger(self, name, username=None):
        """Get or create a Django logger"""
        if username:
            set_current_user(username)

        logger_name = f'fim.{name}'
        logger = logging.getLogger(logger_name)

        # Ensure logger has proper configuration
        if not logger.handlers and logger_name not in self.loggers:
            # Django settings should already configure this
            pass

        self.loggers[logger_name] = logger
        return logger

    def get_directory_logger(self, directory_path, username=None):
        """Get logger for specific directory"""
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory does not exist: {directory_path}")

        log_basename = self._sanitize_basename(directory_path)
        logger_name = f'fim.directory.{log_basename}'

        if logger_name in self.loggers:
            return self.loggers[logger_name]

        if username:
            set_current_user(username)

        logger = logging.getLogger(logger_name)

        log_file = os.path.join(self.logs_dir, f'fim_{log_basename}.log')

        # Add handler if not already present
        if not logger.handlers:
            from logging.handlers import RotatingFileHandler

            handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )

            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)s | %(username)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False

        self.loggers[logger_name] = logger

        logger.info(f"Initialized FIM logging for: {directory_path}")

        return logger

    def log_to_database(self, log_type, level, message, username=None, 
                       directory=None, file_metadata=None, details=None):
        """Log to Django database (FIMLog model)"""
        from fim.models import FIMLog, Directory as DirModel

        try:
            dir_obj = None
            if directory:
                dir_obj, _ = DirModel.objects.get_or_create(
                    path=os.path.normpath(directory),
                    defaults={'is_active': False}
                )

            file_meta_obj = None
            if file_metadata and isinstance(file_metadata, (int, str)):
                from fim.models import FileMetadata
                try:
                    if isinstance(file_metadata, int):
                        file_meta_obj = FileMetadata.objects.get(id=file_metadata)
                    else:
                        file_meta_obj = FileMetadata.objects.filter(
                            change_id=file_metadata
                        ).first()
                except Exception:
                    pass

            # Create log entry
            log_entry = FIMLog.objects.create(
                log_type=log_type,
                level=level,
                message=message[:500],
                details=details or {},
                directory=dir_obj,
                file_metadata=file_meta_obj,
                username=username or 'system',
                ip_address=None  # Can be populated from request if available
            )

            return log_entry.id
        except Exception as e:
            self.get_logger('system', username).error(
                f"Failed to log to database: {str(e)}"
            )
            return None

    def shutdown(self):
        """Cleanup logging resources"""
        clear_current_user()
        for logger in self.loggers.values():
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)
        self.loggers.clear()


fim_logger = DjangoFIMLogger()


def get_directory_logger(directory, username='system'):
    """Get logger for specific directory"""
    return fim_logger.get_directory_logger(directory, username)

def log_change(change_type, file_path, username='system', details=None):
    """Log a file change event"""
    logger = fim_logger.get_logger('changes', username)
    log_message = f"{change_type.upper()}: {file_path}"

    if change_type == 'error':
        logger.error(log_message, extra={'details': details})
    else:
        logger.info(log_message, extra={'details': details})

    fim_logger.log_to_database(
        log_type='change',
        level='error' if change_type == 'error' else 'info',
        message=log_message,
        username=username,
        directory=os.path.dirname(file_path) if os.path.exists(file_path) else None,
        details=details
    )

def log_backup(backup_type, directory, username, status, details=None):
    """Log backup operation"""
    logger = fim_logger.get_logger('backup', username)
    log_message = f"Backup {status}: {directory} ({backup_type})"

    logger.info(log_message, extra={'details': details})

    fim_logger.log_to_database(
        log_type='backup',
        level='info' if status == 'success' else 'error',
        message=log_message,
        username=username,
        directory=directory,
        details=details
    )
