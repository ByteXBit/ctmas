class SecurityAnomalyDetection:
    """Stub Isolation Forest-based anomaly detector."""

    def predict(self, payload) -> float:
        """Return a mock anomaly score in [0, 1]."""
        hr = getattr(payload, "heart_rate", 75.0)
        # Very simple heuristic: deviate from 75 bpm => higher score
        score = min(1.0, abs(hr - 75.0) / 75.0)
        return float(score)


class ThreatModelLogic:
    """Stub rule-based threat classifier."""

    def predict(self, payload, anomaly_score: float) -> dict:
        if anomaly_score > 0.8:
            return {
                "threat_type": "High Anomaly",
                "mitigation_action": "Alert clinical staff",
                "threat_weight": 0.4,
            }
        elif anomaly_score > 0.5:
            return {
                "threat_type": "Moderate Anomaly",
                "mitigation_action": "Increase monitoring frequency",
                "threat_weight": 0.2,
            }
        return {
            "threat_type": "Normal",
            "mitigation_action": "None",
            "threat_weight": 0.0,
        }


class LSTMLogic:
    """Stub LSTM risk predictor."""

    def predict(self, payload) -> float:
        """Return a mock device risk delta in [0, 0.3]."""
        return 0.05


# Singletons
security_anomaly_detector = SecurityAnomalyDetection()
threat_classifier = ThreatModelLogic()
lstm_predictor = LSTMLogic()


class DriftDetectorMock:
    def check_drift(self, payload):
        return False


drift_detector = DriftDetectorMock()
