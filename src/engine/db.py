# src/engine/db.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from engine.models import Base

DATABASE_URL = "sqlite:///./hawiyat_scans.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)
