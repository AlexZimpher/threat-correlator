import os
os.makedirs("data", exist_ok=True)

from sqlalchemy import create_engine, Column, String, Integer, DateTime, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()
DB_PATH = "sqlite:///data/iocs.db"

class IOC(Base):
    __tablename__ = "ioc_blacklist"

    ip = Column(String, primary_key=True)
    confidence = Column(Integer)
    country = Column(String)
    last_seen = Column(DateTime)
    usage = Column(String)
    source = Column(String)

    __table_args__ = (Index("idx_ip", "ip"),)

def get_session():
    engine = create_engine(DB_PATH)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()

