import os

# Database storage and ORM model for ThreatCorrelator.
# Provides functions to connect to the database and define the IOC model.


from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

Base = declarative_base()


def get_engine() -> Engine:
    """
    Create a SQLAlchemy engine for the IOC database.
    Uses TC_DB_PATH environment variable if set (for testing),
    otherwise defaults to 'sqlite:///sampledata/iocs.db'.
    """
    db_path = os.getenv("TC_DB_PATH", "sqlite:///sampledata/iocs.db")
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
        type (str): The type of indicator (ip, domain, etc.)
        confidence (int): Confidence score
        country (str): Country code
        last_seen (datetime): Last seen timestamp
        usage (str): Usage or context
        source (str): Source of the IOC
    """

    __tablename__ = "iocs"
    indicator = Column(String, primary_key=True)
    type = Column(String)
    confidence = Column(Integer)
    country = Column(String)
    last_seen = Column(DateTime)
    usage = Column(String)
    source = Column(String)
