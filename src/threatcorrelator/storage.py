import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Integer, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

# Ensure database directory exists
os.makedirs("data", exist_ok=True)

# SQLAlchemy base and DB path
Base = declarative_base()
DB_PATH = "sqlite:///data/iocs.db"

class IOC(Base):
    """
    SQLAlchemy ORM model for IP-based threat intelligence IOCs.
    """
    __tablename__ = "ioc_blacklist"

    ip = Column(String, primary_key=True)
    confidence = Column(Integer)
    country = Column(String)
    last_seen = Column(DateTime)
    usage = Column(String)
    source = Column(String)

def get_session(db_url: str = DB_PATH):
    """
    Initializes the SQLite database and returns a new SQLAlchemy session.
    Accepts a custom DB URL for testing.
    """
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()

