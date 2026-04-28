import numpy as np
from collections import deque
import json
import os
import hashlib
import time

class TemporalExtractor:
    def __init__(self, window_len=30, stats_file="ml/norm_stats.json"):
        self.window_len = window_len
        self.stats_file = stats_file
        self.buffers = {}
        self.tx_intervals = {}
        self.stats = {}
        self.alpha = 0.99  # EMA lambda for stats
        
        # Load stats if exists
        self.load_stats()
        
    def load_stats(self):
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    self.stats = json.load(f)
            except Exception:
                self.stats = {}
                
    def save_stats(self):
        os.makedirs(os.path.dirname(self.stats_file), exist_ok=True)
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f)
            
    def reset(self, device_id: str):
        if device_id in self.buffers:
            del self.buffers[device_id]
        if device_id in self.tx_intervals:
            del self.tx_intervals[device_id]

    def _approx_entropy(self, U, m, r):
        def _maxdist(x_i, x_j):
            return max([abs(ua - va) for ua, va in zip(x_i, x_j)])

        def _phi(m):
            x = [[U[j] for j in range(i, i + m)] for i in range(len(U) - m + 1)]
            C = [len([1 for x_j in x if _maxdist(x_i, x_j) <= r]) / (len(U) - m + 1.0) for x_i in x]
            return (1.0 / (len(U) - m + 1.0)) * sum([np.log(c) for c in C if c > 0])

        return abs(_phi(m + 1) - _phi(m))
        
    def _spectral_entropy(self, x):
        psd = np.abs(np.fft.rfft(x))**2
        psd_norm = psd / np.sum(psd)
        psd_norm = psd_norm[psd_norm > 0]
        return -np.sum(psd_norm * np.log2(psd_norm))

    def update(self, device_id: str, reading: dict) -> np.ndarray | None:
        if device_id not in self.buffers:
            self.buffers[device_id] = deque(maxlen=self.window_len)
            self.tx_intervals[device_id] = deque(maxlen=self.window_len)
            
        current_time = time.time() * 1000  # ms
        if len(self.tx_intervals[device_id]) > 0:
            last_time = self.tx_intervals[device_id][-1]['ts']
            tx_interval = current_time - last_time
        else:
            tx_interval = 1000.0  # default 1s
            
        payload = json.dumps(reading)
        
        self.tx_intervals[device_id].append({'ts': current_time, 'interval': tx_interval})
        self.buffers[device_id].append({
            'reading': reading,
            'tx_interval_ms': tx_interval,
            'payload_bytes': len(payload),
            'payload_hash': hashlib.sha256(payload.encode()).hexdigest(),
            'ip': reading.get('ip', '192.168.1.100')
        })
        
        if len(self.buffers[device_id]) < self.window_len:
            return None
            
        # compute 20 features
        window = list(self.buffers[device_id])
        readings = [w['reading'] for w in window]
        
        features = np.zeros((self.window_len, 20))
        
        # We need features per row or for the window?
        # The return is shape (30, 20), meaning features for EACH time step.
        # Group 1: raw vitals per step
        for i in range(self.window_len):
            r = readings[i]
            features[i, 0] = r.get('hr_bpm', 75)
            features[i, 1] = r.get('spo2_pct', 98)
            features[i, 2] = r.get('rr_bpm', 16)
            features[i, 3] = r.get('sbp_mmhg', 120)
            features[i, 4] = r.get('dbp_mmhg', 80)
            
            # For window-level stats, we'll compute over the whole window and assign to ALL steps for simplicity, 
            # OR compute rolling stats up to step i. The prompt says "When buffer has 30 readings, compute these 20 features", 
            # and "Return: numpy array of shape (30, 20)". Let's compute window stats and broadcast to all 30 steps,
            # or maybe it just wants a feature vector for each of the 30 readings. 
            
        # Extracted window stats
        ecg_signal = np.array([r.get('ecg', 0.0) for r in readings])
        # If ecg is a single value per reading, some readings don't have it.
        # Fallback to hr_bpm / 100 or something if not present
        if not any('ecg' in r for r in readings):
            ecg_signal = features[:, 0] / 100.0
            
        ecg_mean = np.mean(ecg_signal)
        ecg_std = np.std(ecg_signal) + 1e-6
        ecg_min = np.min(ecg_signal)
        ecg_max = np.max(ecg_signal)
        
        # OLS slope
        x_idx = np.arange(self.window_len)
        poly = np.polyfit(x_idx, ecg_signal, 1)
        ecg_slope = poly[0]
        
        # Zero crossing rate
        ecg_centered = ecg_signal - ecg_mean
        zcr = np.sum(np.diff(np.sign(ecg_centered)) != 0) / self.window_len
        
        app_ent = self._approx_entropy(ecg_signal.tolist(), 2, 0.2 * ecg_std)
        spec_ent = self._spectral_entropy(ecg_signal)
        
        # Group 3
        tx_intervals = [w['tx_interval_ms'] for w in window]
        payload_bytes = [w['payload_bytes'] for w in window]
        
        # Jitter of last 10 intervals
        interval_jitter = []
        for i in range(self.window_len):
            start = max(0, i - 9)
            interval_jitter.append(np.std(tx_intervals[start:i+1]))
            
        # Group 4
        # correlation deviation (e.g., between HR and SBP)
        corr_matrix = np.corrcoef(features[:, 0], features[:, 3])
        corr_hr_sbp = corr_matrix[0, 1] if not np.isnan(corr_matrix[0, 1]) else 0.0
        # enrolled baseline correlation might be missing, assume 0.5
        corr_dev = abs(corr_hr_sbp - 0.5)
        
        # sqi_slope
        sqi_signal = np.array([r.get('sqi', 100.0) for r in readings])
        sqi_slope = np.polyfit(x_idx, sqi_signal, 1)[0]
        
        hashes = [w['payload_hash'][-2:] for w in window] # simple proxy
        hash_counts = {}
        for h in hashes:
            hash_counts[h] = hash_counts.get(h, 0) + 1
        hash_probs = [c/self.window_len for c in hash_counts.values()]
        payload_hash_entropy = -sum(p * np.log2(p) for p in hash_probs)
        
        ips = [w['ip'] for w in window]
        ip_octets = [ip.split('.')[-1] for ip in ips]
        ip_counts = {}
        for ipo in ip_octets:
            ip_counts[ipo] = ip_counts.get(ipo, 0) + 1
        ip_probs = [c/self.window_len for c in ip_counts.values()]
        ip_entropy = -sum(p * np.log2(p) for p in ip_probs)
        
        for i in range(self.window_len):
            features[i, 5] = ecg_mean
            features[i, 6] = ecg_std
            features[i, 7] = ecg_min
            features[i, 8] = ecg_max
            features[i, 9] = ecg_slope
            features[i, 10] = zcr
            features[i, 11] = app_ent
            features[i, 12] = spec_ent
            
            features[i, 13] = tx_intervals[i]
            features[i, 14] = payload_bytes[i]
            features[i, 15] = interval_jitter[i]
            
            features[i, 16] = corr_dev
            features[i, 17] = sqi_slope
            features[i, 18] = payload_hash_entropy
            features[i, 19] = ip_entropy
            
        # Normalization
        if device_id not in self.stats:
            self.stats[device_id] = {'mean': list(np.mean(features, axis=0)), 'var': list(np.var(features, axis=0))}
        else:
            # update EMA
            old_mean = np.array(self.stats[device_id]['mean'])
            old_var = np.array(self.stats[device_id]['var'])
            
            new_mean = np.mean(features, axis=0)
            new_var = np.var(features, axis=0)
            
            ema_mean = self.alpha * old_mean + (1 - self.alpha) * new_mean
            ema_var = self.alpha * old_var + (1 - self.alpha) * new_var
            
            self.stats[device_id]['mean'] = list(ema_mean)
            self.stats[device_id]['var'] = list(ema_var)
            
        # normalize
        mean = np.array(self.stats[device_id]['mean'])
        std = np.sqrt(np.array(self.stats[device_id]['var'])) + 1e-6
        norm_features = (features - mean) / std
        
        # Save every 10 updates or something, we'll just save continuously or caller handles it.
        # Avoid saving synchronously every update, maybe on exit.
        
        return norm_features
