import numpy as np
from sklearn.ensemble import IsolationForest

class SecurityAnomalyDetection:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        # Training on normal heart rate variation [mean_hr, variance]
        dummy_data = np.random.normal(loc=[80.0, 5.0], scale=[10.0, 2.0], size=(100, 2))
        self.model.fit(dummy_data)
        
        self.base_threshold = 0.5
        self.adaptive_factor = 0.1
        self.recent_anomalies = 0
        
    def predict(self, payload):
        """
        Returns an anomaly score between 0 and 1.
        Applies adaptive thresholding based on recent history.
        """
        hr = payload.heart_rate
        # Calculate variance roughly from the ECG signal mock
        variance = np.var(payload.ecg_signal) if len(payload.ecg_signal) > 0 else 0
        
        features = np.array([[hr, variance]])
        score = self.model.score_samples(features)[0]
        
        normalized_score = min(max((abs(score) - 0.4) / 0.4, 0.0), 1.0)
        
        # Data tampering detection: impossible heart rates
        if hr > 220 or hr < 30:
            normalized_score = 1.0
            
        # Adaptive Threshold logic
        current_threshold = self.base_threshold + (self.adaptive_factor * self.recent_anomalies)
        current_threshold = min(current_threshold, 0.9) # cap threshold
        
        # If score exceeds adaptive threshold, consider it an anomaly and increase counter
        if normalized_score > current_threshold:
            self.recent_anomalies = min(self.recent_anomalies + 1, 5) # cap recent anomalies count
        else:
            self.recent_anomalies = max(self.recent_anomalies - 0.5, 0) # decay
            
        return float(normalized_score)
