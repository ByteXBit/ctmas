ATTACK_CLASSES = {
    "A1": {
        "class": "False Data Injection (FDI)",
        "mitre_id": "T0832",
        "impact_weight": 8,
        "features": ["hr_bpm", "ecg_slope", "correlation_deviation"],
        "mitigation": [
            "Freeze clinical display, show verification banner",
            "Route raw sensor to secondary display",
            "Request manual vital signs measurement"
        ]
    },
    "A2": {
        "class": "Device Spoofing",
        "mitre_id": "T0886",
        "impact_weight": 9,
        "features": ["interval_jitter", "payload_hash_entropy", "sqi_slope"],
        "mitigation": [
            "Suspend device session",
            "Trigger re-enrollment",
            "Alert network security team",
            "Cross-reference with physical device log"
        ]
    },
    "A3": {
        "class": "Denial of Service",
        "mitre_id": "T0814",
        "impact_weight": 7,
        "features": ["tx_interval_ms", "payload_bytes", "interval_jitter"],
        "mitigation": [
            "Activate backup telemetry feed",
            "Switch to local alarm mode",
            "Page network security team",
            "Log attack start timestamp"
        ]
    },
    "A4": {
        "class": "Sensor Delay Injection",
        "mitre_id": "T0856",
        "impact_weight": 6,
        "features": ["timestamp_delta", "bp_lag", "rolling_timestamp_deviation"],
        "mitigation": [
            "Flag all readings as temporally unreliable",
            "Trigger immediate manual patient assessment",
            "Alert clinical team of potential monitoring gap",
            "Log delay profile for forensic review"
        ]
    },
    "A5": {
        "class": "Replay Attack",
        "mitre_id": "T0839",
        "impact_weight": 8,
        "features": ["autocorrelation_score", "rolling_hash_match"],
        "mitigation": [
            "Reject all readings with matched hash",
            "Force new session token for device",
            "Alert security team",
            "Audit last 10 minutes of session data"
        ]
    },
    "A6": {
        "class": "AI Model Evasion",
        "mitre_id": "T0830",
        "impact_weight": 10,
        "features": ["minimal_reconstruction_error"],
        "mitigation": [
            "Override UTS +20 regardless of S_lstm",
            "Trigger adversarial retraining pipeline",
            "Notify security team of active evasion attempt",
            "Switch to Isolation Forest only mode temporarily"
        ]
    },
    "A7": {
        "class": "Ransomware / Encryption",
        "mitre_id": "T0884",
        "impact_weight": 10,
        "features": ["db_write_failures", "disk_io_spike", "api_response_time_spike"],
        "mitigation": [
            "Isolate database service",
            "Activate read-only emergency mode",
            "Alert CISO immediately",
            "Initiate backup restoration procedure"
        ]
    }
}

def classify_attack(top_anomalous_features: list, predictive_alert=False, mse_low=False) -> dict:
    if mse_low and predictive_alert:
        cls = ATTACK_CLASSES["A6"]
        return {
            "class": cls["class"],
            "mitre_id": cls["mitre_id"],
            "mitigation": cls["mitigation"],
            "confidence": 0.95,
            "patient_impact": "CRITICAL"
        }
        
    scores = {k: 0 for k in ATTACK_CLASSES.keys()}
    
    for feature in top_anomalous_features:
        for k, v in ATTACK_CLASSES.items():
            if feature in v["features"]:
                scores[k] += v["impact_weight"]
                
    best_class = max(scores, key=scores.get)
    if scores[best_class] == 0:
        return {
            "class": "Unknown Intrusion",
            "mitre_id": "Unknown",
            "mitigation": ["Initiate forensic review", "Isolate device logs"],
            "confidence": 0.0,
            "patient_impact": "UNKNOWN"
        }
        
    cls = ATTACK_CLASSES[best_class]
    return {
        "class": cls["class"],
        "mitre_id": cls["mitre_id"],
        "mitigation": cls["mitigation"],
        "confidence": min(1.0, scores[best_class] / 20.0), # arbitrary confidence proxy
        "patient_impact": "HIGH" if cls["impact_weight"] >= 8 else "MEDIUM"
    }
