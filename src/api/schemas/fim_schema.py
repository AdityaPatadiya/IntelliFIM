from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class FIMStartRequest(BaseModel):
    directories: List[str]
    excluded_files: Optional[List[str]] = []

class FIMStopRequest(BaseModel):
    directories: List[str]

class FIMAddPathRequest(BaseModel):
    directory: str

class FIMRestoreRequest(BaseModel):
    path_to_restore: str

class FIMStatusResponse(BaseModel):
    is_monitoring: bool
    watched_directories: List[str]
    active_directories: List[str]
    total_configured: int
    total_active: int

class FIMChangesResponse(BaseModel):
    added: Dict[str, Any]
    modified: Dict[str, Any]
    deleted: Dict[str, Any]
    total_changes: int

class FIMLogsResponse(BaseModel):
    directory: str
    log_file: str
    content: str
