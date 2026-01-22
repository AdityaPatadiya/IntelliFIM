"""
Thread pool utility for offloading CPU-intensive operations.
"""
import os
import concurrent.futures
from typing import Callable, Any
import threading
from functools import wraps


class ThreadPoolManager:
    """Manages a thread pool for CPU-intensive operations."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_pool()
        return cls._instance

    def _init_pool(self):
        """Initialize thread pool with optimal workers"""
        cpu_count = os.cpu_count() or 4
        self.max_workers = min(max(2, cpu_count - 1), 4)
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers = self.max_workers,
            thread_name_prefix="fim_worker"
        )
        print(f"FIM ThreadPool initialized with {self.max_workers} workers")

    def submit(self,fn: Callable, *args, **kwargs) -> concurrent.futures.Future:
        """Submit a task to the thread pool."""
        return self.executor.submit(fn, *args, **kwargs)

    def shutdown(self, wait: bool = True):
        """Shutdown the thread pool."""
        self.executor.shutdown(wait=wait)
        print("FIM ThreadPool shutdown complete.")


thread_pool = ThreadPoolManager()

def run_in_thread_pool(func):
    """Decorator to run a function in the thread pool."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        return thread_pool.submit(func, *args, **kwargs)
    return wrapper
