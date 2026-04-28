import os
import json
import math
import sqlite3
import requests
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime

import sys
sys.path.append(os.path.dirname(__file__))
from temporal_extractor import TemporalExtractor
from attack_taxonomy import classify_attack
from cadre import CADRE

router = APIRouter(prefix="/api")

temporal_extractor = TemporalExtractor(stats_file=os.path.join(os.path.dirname(__file__), "ml", "norm_stats.json"))

# Optionally use remote microservices; fall back to local computation
LSTM_URL = os.getenv("LSTM_URL", "http://lstm_inference:8001")
CADRE_URL = os.getenv("CADRE_URL", "http://cadre_engine:8002")

# Local CADRE engine (always available, used as fallback)
_db_path = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "medical_cps.db"))
local_cadre = CADRE(db_path=_db_path)

# In-memory transient dashboard state
dashboard_state = {
    "forecast": [],
    "forecast_ci": [],
    "predictive_alert": False,
    "uts": 0.0,
    "severity": "NOMINAL",
    "trust_score": 1.0,
    "attack_class": None,
    "mitre_id": None,
    # Extra enriched metrics
    "s_iso": 0.0,
    "s_lstm": 0.0,
    "s_pred": 0.0,
    "action": "none",
    "last_updated": None,
}


class VitalsPayload(BaseModel):
    timestamp: str
    device_id: str
    ecg_signal: list
    heart_rate: float
    spo2_pct: Optional[float] = 98.0
    rr_bpm: Optional[float] = 16.0
    sbp_mmhg: Optional[float] = 120.0
    dbp_mmhg: Optional[float] = 80.0
    ip: Optional[str] = "192.168.1.100"
    sqi: Optional[float] = 100.0


class ConfirmAttack(BaseModel):
    device_id: str


class ProbeRequest(BaseModel):
    device_id: str
    eps: float


def _try_lstm(device_id: str, window_list: list) -> dict:
    """Call remote LSTM service, fall back to local mock on failure."""
    try:
        res = requests.post(
            f"{LSTM_URL}/anomaly_score",
            json={"device_id": device_id, "window": window_list},
            timeout=2,
        )
        return res.json()
    except Exception:
        import numpy as np
        arr = _np_array(window_list)
        if arr is None:
            return {"score_lstm": 0.0, "score_pred": 0.0, "predictive_alert": False,
                    "top3_features": [], "mse": 0.0, "forecast_points": [], "forecast_ci": []}

        # ── S_lstm: reconstruction MSE proxy ─────────────────────────────────
        # Compute per-feature variance across the time axis (normalized window).
        # Typical normalized variance for stable signals ≈ 0.05-0.2.
        # Use mean absolute deviation from a simple linear trend as MSE proxy.
        feat_var = np.var(arr, axis=0)          # shape (20,)
        # Residuals from a linear fit per feature (proxy for unexplained variance)
        x = np.arange(arr.shape[0])
        residuals = []
        for f in range(arr.shape[1]):
            coef = np.polyfit(x, arr[:, f], 1)
            trend = np.polyval(coef, x)
            residuals.append(np.mean((arr[:, f] - trend) ** 2))
        mse_proxy = float(np.mean(residuals))   # ≈ 0.01-0.3 for typical signals

        # Scale: mse=0 → score_lstm=0, mse=0.5 → score_lstm=35 (cap)
        score_lstm = min(35.0, mse_proxy * 70.0)

        # ── Top-3 most anomalous features by residual ─────────────────────────
        feature_names = ["hr_bpm", "spo2_pct", "rr_bpm", "sbp_mmhg", "dbp_mmhg",
                         "ecg_mean", "ecg_std", "ecg_min", "ecg_max", "ecg_slope",
                         "ecg_zcr", "ecg_app_entropy", "ecg_spec_entropy",
                         "tx_interval_ms", "payload_bytes", "interval_jitter",
                         "corr_deviation", "sqi_slope", "payload_hash_entropy", "ip_entropy"]
        top3_idx = np.argsort(residuals)[-3:][::-1].tolist()
        top3 = [feature_names[i] for i in top3_idx if i < len(feature_names)]

        # ── S_pred: linear HR extrapolation ──────────────────────────────────
        hr_series = arr[:, 0]          # feature 0 = hr_bpm (normalized)
        # Fit a trend line and extrapolate 5 steps forward
        coef_hr = np.polyfit(x, hr_series, 1)
        future_steps = np.arange(arr.shape[0], arr.shape[0] + 5)
        hr_future_norm = np.polyval(coef_hr, future_steps)

        # Denormalize using stored stats if available
        try:
            stats = local_cadre._init_db and temporal_extractor.stats.get(device_id)
        except Exception:
            stats = None

        if stats:
            hr_mean = stats['mean'][0]
            hr_std = float(np.sqrt(max(stats['var'][0], 1e-6)))
            hr_future = hr_future_norm * hr_std + hr_mean
        else:
            # Rough denorm: assume HR centred around 75 with std≈15
            hr_future = hr_future_norm * 15.0 + 75.0

        predictive_alert = bool(np.any(hr_future > 150) or np.any(hr_future < 40))
        score_pred = 25.0 if predictive_alert else 0.0

        # Build simple forecast / CI arrays (5 steps × 20 features)
        forecast_pts  = [[float(hr_future[i])] + [0.0]*19 for i in range(5)]
        ci_margin     = float(np.std(hr_series) * 15.0 * 1.96) if stats else 10.0
        forecast_ci   = [[float(hr_future[i]) + ci_margin] + [0.0]*19 for i in range(5)]

        return {
            "score_lstm":      float(score_lstm),
            "score_pred":      float(score_pred),
            "predictive_alert":predictive_alert,
            "top3_features":   top3,
            "mse":             float(mse_proxy),
            "forecast_points": forecast_pts,
            "forecast_ci":     forecast_ci,
        }



def _np_array(window_list):
    try:
        import numpy as np
        return np.array(window_list)
    except Exception:
        return None


def _try_cadre(device_id, s_iso, s_lstm, s_pred, acuity_level=0) -> dict:
    """Call remote CADRE service, fall back to local CADRE engine on failure."""
    try:
        res = requests.post(
            f"{CADRE_URL}/compute_uts",
            json={
                "device_id": device_id,
                "s_iso": s_iso,
                "s_lstm": s_lstm,
                "s_pred": s_pred,
                "acuity_level": acuity_level,
            },
            timeout=2,
        )
        return res.json()
    except Exception:
        return local_cadre.compute_uts(device_id, s_iso, s_lstm, s_pred, acuity_level)


def _try_confirm_attack(device_id: str):
    try:
        requests.post(f"{CADRE_URL}/confirm_attack", json={"device_id": device_id}, timeout=2)
    except Exception:
        local_cadre.confirm_attack(device_id)


def _try_log_prediction(log_entry: dict):
    try:
        requests.post(f"{CADRE_URL}/log_prediction", json=log_entry, timeout=2)
    except Exception:
        local_cadre.log_prediction(log_entry)


@router.post("/vitals")
def ingest_vitals(payload: VitalsPayload, background_tasks: BackgroundTasks):
    reading = payload.dict()
    reading["hr_bpm"] = payload.heart_rate
    reading["ecg"] = payload.ecg_signal[0] if payload.ecg_signal else 0.0

    features_window = temporal_extractor.update(payload.device_id, reading)

    if features_window is not None:
        lstm_res = _try_lstm(payload.device_id, features_window.tolist())

        s_lstm = lstm_res.get("score_lstm", 0.0)
        s_pred = lstm_res.get("score_pred", 0.0)
        pred_alert = lstm_res.get("predictive_alert", False)
        top3 = lstm_res.get("top3_features", [])

        # S_iso: scale anomaly from isolation-style heuristic [0, 40]
        hr = payload.heart_rate
        s_iso = min(40.0, abs(hr - 75.0) / 75.0 * 40.0)

        cadre_res = _try_cadre(payload.device_id, s_iso, s_lstm, s_pred)

        uts = cadre_res["uts"]
        severity = cadre_res["severity"]
        action = cadre_res.get("action", "none")
        trust_score = cadre_res["trust_score"]
        is_attack = uts >= 61  # THREAT or CRITICAL

        attack_class = None
        mitre_id = None
        if is_attack or pred_alert:
            tax = classify_attack(
                top3,
                predictive_alert=pred_alert,
                mse_low=(lstm_res.get("mse", 0) < 0.5),
            )
            attack_class = tax["class"]
            mitre_id = tax["mitre_id"]
            if is_attack:
                _try_confirm_attack(payload.device_id)

        log_entry = {
            "timestamp": payload.timestamp,
            "device_id": payload.device_id,
            "uts": uts,
            "severity": severity,
            "attack_class": attack_class,
            "mitre_id": mitre_id,
            "s_iso": s_iso,
            "s_lstm": s_lstm,
            "s_pred": s_pred,
            "forecast": lstm_res.get("forecast_points", []),
            "is_attack": 1 if is_attack else 0,
        }
        background_tasks.add_task(_try_log_prediction, log_entry)

        dashboard_state.update({
            "forecast": lstm_res.get("forecast_points", []),
            "forecast_ci": lstm_res.get("forecast_ci", []),
            "predictive_alert": pred_alert,
            "uts": uts,
            "severity": severity,
            "trust_score": trust_score,
            "attack_class": attack_class,
            "mitre_id": mitre_id,
            "s_iso": s_iso,
            "s_lstm": s_lstm,
            "s_pred": s_pred,
            "action": action,
            "last_updated": payload.timestamp,
        })

        return cadre_res

    return {"status": "buffering"}


@router.get("/dashboard")
def get_dashboard():
    return dashboard_state


@router.get("/threat-model-state")
def get_threat_model_state():
    try:
        conn = sqlite3.connect(_db_path)
        c = conn.cursor()
        c.execute(
            "SELECT device_id, trust_score, uts_history, attack_count, acuity_level, status, last_alert_time "
            "FROM threat_model_state"
        )
        rows = c.fetchall()
        conn.close()

        result = []
        for r in rows:
            result.append({
                "device_id": r[0],
                "trust_score": r[1],
                "uts_history": json.loads(r[2] or "[]"),
                "attack_count": r[3],
                "acuity_level": r[4],
                "status": r[5],
                "last_alert_time": r[6],
            })
        return result
    except Exception:
        return []


@router.post("/confirm-attack")
def confirm_attack(payload: ConfirmAttack):
    try:
        _try_confirm_attack(payload.device_id)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/adversarial-probe")
def run_adversarial_probe(payload: ProbeRequest):
    window = list(temporal_extractor.buffers.get(payload.device_id, []))
    if len(window) < temporal_extractor.window_len:
        raise HTTPException(status_code=400, detail="Not enough data in buffer yet (need 30 readings)")

    features = temporal_extractor.update(payload.device_id, window[-1]["reading"])
    try:
        res = requests.post(
            f"{LSTM_URL}/adversarial-probe",
            json={"device_id": payload.device_id, "eps": payload.eps, "window": features.tolist()},
            timeout=10,
        )
        return res.json()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LSTM service unavailable: {e}")


@router.get("/alerts")
def get_alerts():
    try:
        conn = sqlite3.connect(_db_path)
        c = conn.cursor()
        c.execute(
            "SELECT timestamp, device_id, uts, severity, attack_class, mitre_id, is_attack "
            "FROM prediction_log WHERE is_attack=1 ORDER BY id DESC LIMIT 50"
        )
        rows = c.fetchall()
        conn.close()
        return [
            {
                "timestamp": r[0],
                "device_id": r[1],
                "uts": r[2],
                "severity": r[3],
                "attack_class": r[4],
                "mitre_id": r[5],
                "is_attack": bool(r[6]),
            }
            for r in rows
        ]
    except Exception:
        return []


@router.get("/resilience")
def get_resilience():
    try:
        conn = sqlite3.connect(_db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM prediction_log")
        total = c.fetchone()[0] or 1
        c.execute("SELECT COUNT(*) FROM prediction_log WHERE is_attack=1")
        attacks = c.fetchone()[0]
        c.execute("SELECT AVG(uts) FROM prediction_log")
        avg_uts = c.fetchone()[0] or 0.0
        conn.close()

        uptime_pct = round((1 - attacks / total) * 100, 1)
        return {
            "total_ticks": total,
            "attack_ticks": attacks,
            "normal_ticks": total - attacks,
            "uptime_pct": uptime_pct,
            "avg_uts": round(avg_uts, 1),
            "resilience_score": round(max(0, uptime_pct - (avg_uts / 10)), 1),
        }
    except Exception:
        return {"total_ticks": 0, "attack_ticks": 0, "normal_ticks": 0, "uptime_pct": 100.0, "avg_uts": 0.0, "resilience_score": 100.0}
