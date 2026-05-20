# data-plane/auth_backend/tests/conftest.py
import os
import tempfile

import pytest


@pytest.fixture
def tmp_db_path():
    """Temp-file SQLite path for tests; cleaned up after."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
