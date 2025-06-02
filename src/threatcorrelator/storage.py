import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

# Ensure 'data' directory exists
os.makedirs("data", exist_ok=True)

Base = declarative_base()

def get_engine():
    """
    Create a SQLite engine.
    Uses TC_DB_PATH environment variable if set (for testing), 
    otherwise defaults to 'sqlite:///data/iocs.db'.
    """
    db_path = os.getenv("TC_DB_PATH", "sqlite:///data/iocs.db")
    return create_engine(db_path, echo=False)

def get_session():
    """
    Initialize the database (creating tables if needed) and return a new session.
    """
    engine = get_engine()
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()

class IOC(Base):
    """
    SQLAlchemy ORM model for threat intelligence indicators (IP or domain).
    """

    __tablename__ = "ioc_blacklist"

    indicator = Column(String, primary_key=True)  # Unified field for IP or domain
    confidence = Column(Integer)
    country = Column(String)
    last_seen = Column(DateTime)
    usage = Column(String)
    source = Column(String)

