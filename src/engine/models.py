# src/engine/models.py
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class ScanJob(Base):
    __tablename__ = 'scan_jobs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, unique=True, nullable=False)
    user_project = Column(String, nullable=True)
    parameters = Column(Text, nullable=True)
    status = Column(String, default='pending')
    result_file = Column(String, nullable=True)
    scan_stats = Column(Text, nullable=True)  # JSON string of stats
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
