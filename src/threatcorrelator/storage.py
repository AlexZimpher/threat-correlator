import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

# Ensure 'data' directory exists for SQLite
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
    Initialize the database (creating tables if needed) and return a session.
    """
    engine = get_engine()
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()

class IOC(Base):
    """
    ORM model for a threat intelligence indicator (IP, domain, URL, hash, etc.).
    Fields:
        - indicator: The IOC value (IP, domain, etc.)
        - confidence: Confidence score
        - country: Country code
        - last_seen: Last seen timestamp
        - usage: Usage type or context
        - source: Source of the IOC
        - type: IOC type (e.g. IPv4, domain, URL, hash)
    """
    __tablename__ = "ioc_blacklist"
    indicator = Column(String, primary_key=True)  # IP, domain, etc.
    confidence = Column(Integer, nullable=True)
    country = Column(String, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    usage = Column(String, nullable=True)
    source = Column(String, nullable=True)
    type = Column(String, nullable=True)  # e.g. IPv4, domain, URL, hash
