from sqlalchemy import Column, Integer, String, Float, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class SensorEvent(Base):
    __tablename__ = "sensor_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, index=True)
    device_id = Column(String, index=True)
    ecg_signal = Column(Text) # JSON string
    heart_rate = Column(Float)

class ThreatIncident(Base):
    __tablename__ = "threat_incidents"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    device_id = Column(String)
    anomaly_score = Column(Float)
    threat_type = Column(String)
    risk_score = Column(Float)
    mitigation_action = Column(Text)
    status = Column(String, default="unacknowledged")

# SQLite setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./medical_cps.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
