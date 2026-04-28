import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.models import SessionLocal, SensorEvent, ThreatIncident
from app.schemas.prediction_schema import SensorPayload, PredictionOut, IncidentOut
from app.services.ml_service import security_anomaly_detector, threat_classifier, lstm_predictor
from typing import List

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/predict", response_model=PredictionOut)
def predict_threat(payload: SensorPayload, db: Session = Depends(get_db)):
    
    # 1. Edge AI (Anomaly Detection)
    anomaly_score = security_anomaly_detector.predict(payload)
    
    # 2. Security Layer (Threat Modeling Engine)
    threat_info = threat_classifier.predict(payload, anomaly_score)
    threat_type = threat_info["threat_type"]
    mitigation_action = threat_info["mitigation_action"]
    threat_weight = threat_info["threat_weight"]
    
    # 3. Cloud (Logging + Prediction)
    device_risk = lstm_predictor.predict(payload)
    
    # Calculate unified risk score — clamped to [0, 1]
    risk_score = min(1.0, anomaly_score + threat_weight + device_risk)
    
    # Store Database events
    event = SensorEvent(
        timestamp=payload.timestamp,
        device_id=payload.device_id,
        ecg_signal=json.dumps(payload.ecg_signal),
        heart_rate=payload.heart_rate
    )
    db.add(event)
    
    # If high risk or anomaly, create incident
    if risk_score > 0.8 or threat_type != "Normal":
        incident = ThreatIncident(
            timestamp=payload.timestamp,
            device_id=payload.device_id,
            anomaly_score=anomaly_score,
            threat_type=threat_type,
            risk_score=risk_score,
            mitigation_action=mitigation_action
        )
        db.add(incident)
        
    db.commit()

    # --- ATM-PSA Integration (uses local fallbacks when microservices are down) ---
    try:
        import sys, os
        sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        from api_extensions import (
            temporal_extractor, dashboard_state,
            _try_lstm, _try_cadre, _try_confirm_attack, _try_log_prediction
        )
        from attack_taxonomy import classify_attack

        reading = {
            'hr_bpm': payload.heart_rate,
            'ecg': payload.ecg_signal[0] if payload.ecg_signal else 0.0,
            'spo2_pct': 98.0, 'rr_bpm': 16.0,
            'sbp_mmhg': 120.0, 'dbp_mmhg': 80.0,
            'ip': '192.168.1.100', 'sqi': 100.0,
            'timestamp': payload.timestamp
        }

        features_window = temporal_extractor.update(payload.device_id, reading)
        if features_window is not None:
            lstm_res   = _try_lstm(payload.device_id, features_window.tolist())
            s_lstm     = lstm_res.get('score_lstm', 0.0)
            s_pred     = lstm_res.get('score_pred', 0.0)
            pred_alert = lstm_res.get('predictive_alert', False)
            top3       = lstm_res.get('top3_features', [])
            s_iso      = min(40.0, anomaly_score * 40.0)

            cadre_res   = _try_cadre(payload.device_id, s_iso, s_lstm, s_pred)
            uts         = cadre_res['uts']
            severity    = cadre_res['severity']
            action      = cadre_res.get('action', 'none')
            trust_score = cadre_res['trust_score']
            is_attack   = (uts >= 61)

            attack_class = mitre_id = None
            if is_attack or pred_alert:
                tax = classify_attack(top3, predictive_alert=pred_alert,
                                      mse_low=(lstm_res.get('mse', 0) < 0.5))
                attack_class = tax['class']
                mitre_id     = tax['mitre_id']
                if is_attack:
                    _try_confirm_attack(payload.device_id)

            log_entry = {
                'timestamp': payload.timestamp, 'device_id': payload.device_id,
                'uts': uts, 'severity': severity,
                'attack_class': attack_class, 'mitre_id': mitre_id,
                's_iso': s_iso, 's_lstm': s_lstm, 's_pred': s_pred,
                'forecast': lstm_res.get('forecast_points', []),
                'is_attack': 1 if is_attack else 0
            }
            _try_log_prediction(log_entry)

            dashboard_state.update({
                'forecast':        lstm_res.get('forecast_points', []),
                'forecast_ci':     lstm_res.get('forecast_ci', []),
                'predictive_alert':pred_alert,
                'uts':             uts,
                'severity':        severity,
                'trust_score':     trust_score,
                'attack_class':    attack_class,
                'mitre_id':        mitre_id,
                's_iso':           s_iso,
                's_lstm':          s_lstm,
                's_pred':          s_pred,
                'action':          action,
                'last_updated':    payload.timestamp,
            })
    except Exception as e:
        print('ATM-PSA integration error:', e)
    # --- END ATM-PSA ---

    
    return PredictionOut(
        anomaly_score=anomaly_score,
        threat_type=threat_type,
        risk_score=risk_score,
        mitigation_action=mitigation_action
    )

@router.get("/incidents", response_model=List[IncidentOut])
def get_incidents(db: Session = Depends(get_db)):
    incidents = db.query(ThreatIncident).order_by(ThreatIncident.id.desc()).limit(50).all()
    return incidents

@router.patch("/incidents/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(ThreatIncident).filter(ThreatIncident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = "acknowledged"
    db.commit()
    return {"message": "Incident acknowledged"}
