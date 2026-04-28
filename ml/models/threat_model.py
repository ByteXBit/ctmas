class ThreatModelLogic:
    def __init__(self):
        self.threats = {
            "Normal": {"desc": "Normal physiological variance", "weight": 0.0, "mitigation": "No action required."},
            "data_injection": {"desc": "Fake ECG/heart data detected", "weight": 0.6, "mitigation": "Isolate sensor and invalidate recent batch."},
            "dos": {"desc": "Sensor unavailability or latency", "weight": 0.4, "mitigation": "Initiate fallback sensor node."},
            "spoofing": {"desc": "Fake device identity", "weight": 0.8, "mitigation": "Revoke device certificate immediately."}
        }
        
    def predict(self, payload, anomaly_score):
        threat_key = "Normal"
        
        # Check for Dos (e.g. flatline ECG but device claims active)
        if len(payload.ecg_signal) > 0 and sum(payload.ecg_signal) == 0 and anomaly_score > 0.5:
            threat_key = "dos"
            
        # Check for False Data Injection (impossible heart rates with high anomaly)
        elif payload.heart_rate > 220 or payload.heart_rate < 30:
            threat_key = "data_injection"
            
        # Spoofing (simulated via missing or invalid device id formatting, assuming 'device_' prefix is normal)
        elif not payload.device_id.startswith("server_node_"):
            threat_key = "spoofing"
            
        elif anomaly_score > 0.8:
            threat_key = "data_injection" # Generic high anomaly default
            
        threat_info = self.threats[threat_key]
        
        return {
            "threat_type": threat_key,
            "threat_weight": threat_info["weight"],
            "mitigation_action": threat_info["mitigation"]
        }
