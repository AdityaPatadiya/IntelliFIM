import logging
import os
from pathlib import Path
import re

from src.utils.timestamp import timezone


class UsernameFilter(logging.Filter):
    def __init__(self, username):
        super().__init__()
        self.username = username
    
    def filter(self, record):
        record.username = self.username
        return True


class configure_logger:
    def __init__(self):
        """Initialize logger registry and ensure logs directory exists"""
        self.loggers = {}
        self.logs_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "..", "logs"))
        Path(self.logs_dir).mkdir(parents=True, exist_ok=True)

    def _sanitize_basename(self, directory):
        """
        Extract and sanitize the final directory name
        Example: 
        - Input: '/var/log/app' → Returns: 'app'
        - Input: 'C:\\Program Files\\App' → Returns: 'App'
        """
        basename = os.path.basename(os.path.normpath(directory))
        return re.sub(r'[\\/*?:"<>|]', '_', basename).strip('_')

    def _setup_logger(self, name, username=None):
        """Setup a dedicated logger for database operation"""
        self.logger = self._get_global_logger(f"{name}", username)
        return self.logger

    def _get_global_logger(self, name, username=None):
        """
        Get or create a global logger for DB, Backup, Authentication
        """
        if name is self.loggers:
            return self.loggers[name]

        logger = logging.getLogger(f"FIM_{name}")

        if not logger.handlers:
            log_file = os.path.join(self.logs_dir, f"{name}.log")

            handler = logging.FileHandler(log_file, encoding='utf-8')
            handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(username)s | %(message)s",
                datefmt=timezone()[0]
            ))

            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
            logger.addFilter(UsernameFilter(username))

            logger.info(f"Initialized {name} logging")

        self.loggers[name] = logger
        return logger

    def _get_or_create_logger(self, username, directory, file_name=None):
        """
        Get or create a configured logger for the directory
        Returns: Configured Logger object
        Raises: FileNotFoundError if directory doesn't exist
        """
        normalized_dir = os.path.normpath(directory)
        if not os.path.exists(normalized_dir):
            raise FileNotFoundError(f"Directory {normalized_dir} does not exist")

        log_basename = self._sanitize_basename(normalized_dir)
        if normalized_dir in self.loggers:
            return self.loggers[normalized_dir]

        logger = logging.getLogger(f"FIM_{log_basename}")

        if not logger.handlers:  # Only configure if not already set up
            log_file = os.path.join(self.logs_dir, f"FIM_{log_basename}.log")

            handler = logging.FileHandler(
                log_file if file_name is None else file_name,
                encoding='utf-8'  # Ensure UTF-8 support for special characters
            )
            handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(username)s | %(message)s",
                datefmt = timezone()[0]
            ))

            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False  # Prevent duplicate logs

            logger.addFilter(UsernameFilter(username))

            logger.info(f"Initialized FIM logging for: {normalized_dir}")

        self.loggers[normalized_dir] = logger
        return logger


    def shutdown(self):
        """Safely close all logging resources"""
        for logger in self.loggers.values():
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)
        self.loggers.clear()
