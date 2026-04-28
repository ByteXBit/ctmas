from pydantic import BaseModel
from typing import List, Optional

class SensorPayload(BaseModel):
    timestamp: str
    device_id: str
    ecg_signal: List[float]
    heart_rate: float

class IncidentOut(BaseModel):
    id: int
    timestamp: str
    device_id: str
    anomaly_score: float
    threat_type: str
    risk_score: float
    mitigation_action: str
    status: str

class PredictionOut(BaseModel):
    anomaly_score: float
    threat_type: str
    risk_score: float
    mitigation_action: str
