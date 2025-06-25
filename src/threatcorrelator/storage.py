import os

# Database storage and ORM model for ThreatCorrelator.
# Secure, robust, and clearly commented for maintainability.


from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

Base = declarative_base()

def get_engine() -> Engine:
    """
    Create a SQLAlchemy engine for the IOC database.
    Uses TC_DB_PATH environment variable if set (for testing),
    otherwise defaults to 'sqlite:///data/iocs.db'.
    """
    db_path = os.getenv("TC_DB_PATH", "sqlite:///data/iocs.db")
    return create_engine(db_path, echo=False)

def get_session(db_url: str | None = None) -> Session:
    """
    Initialize the database (creating tables if needed) and return a session.
    Accepts an optional db_url for test isolation.
    """
    engine = get_engine() if db_url is None else create_engine(db_url, echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()

class IOC(Base):
    """
    ORM model for a threat intelligence indicator (IP, domain, URL, hash, etc.).
    Fields:
        indicator (str): The IOC value (IP, domain, etc.)
        confidence (int): Confidence score
        country (str): Country code
        last_seen (datetime): Last seen timestamp
        usage (str): Usage type or context
        source (str): Source of the IOC
        type (str): IOC type (e.g. IPv4, domain, URL, hash)
    """
    __tablename__ = "ioc_blacklist"
    indicator = Column(String, primary_key=True)  # IP, domain, etc.
    confidence = Column(Integer, nullable=True)
    country = Column(String, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    usage = Column(String, nullable=True)
    source = Column(String, nullable=True)
    type = Column(String, nullable=True)  # e.g. IPv4, domain, URL, hash
