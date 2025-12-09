"""
fim_models.py
--------------
Contains ORM models for File Integrity Monitoring (fim_db)
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from src.api.database.connection import FimBase


class Directory(FimBase):
    __tablename__ = "directories"
    id = Column(Integer, primary_key=True, index=True)
    path = Column(String(500), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    files = relationship("FileMetadata", back_populates="directory")

class FileMetadata(FimBase):
    __tablename__ = "file_metadata"
    id = Column(Integer, primary_key=True, index=True)
    directory_id = Column(Integer, ForeignKey('directories.id'), nullable=False)
    item_path = Column(String(500), nullable=False)
    item_type = Column(String(10), nullable=False)
    hash = Column(String(128), nullable=False)
    last_modified = Column(DateTime, nullable=False)
    status = Column(String(50), nullable=False)
    detected_at = Column(DateTime, default=datetime.now)

    directory = relationship("Directory", back_populates="files")
