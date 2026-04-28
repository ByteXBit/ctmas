import os
import json
import sqlite3
import math
from datetime import datetime

class CADRE:
    def __init__(self, db_path="/data/medical_cps.db"):
        self.db_path = db_path
        self.w_iso = float(os.getenv("CADRE_W_ISO", "1.0"))
        self.w_lstm = float(os.getenv("CADRE_W_LSTM", "1.0"))
        self.w_pred = float(os.getenv("CADRE_W_PRED", "1.0"))
        self.kappa = float(os.getenv("CADRE_KAPPA", "0.15"))
        self.dev_delta_attack = float(os.getenv("DEVICE_TRUST_DELTA_ATTACK", "0.15"))
        self.dev_delta_clean = float(os.getenv("DEVICE_TRUST_DELTA_CLEAN", "0.01"))
        self.quarantine_thresh = float(os.getenv("DEVICE_QUARANTINE_THRESHOLD", "0.10"))
        
        self._init_db()

    def _init_db(self):
        # We assume the database directory is already created by main app
        os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else '.', exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS threat_model_state (
                device_id TEXT PRIMARY KEY,
                trust_score REAL DEFAULT 1.0,
                uts_history TEXT DEFAULT '[]',
                attack_count INTEGER DEFAULT 0,
                last_alert_time TEXT,
                acuity_level INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active'
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS prediction_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                device_id TEXT,
                uts REAL,
                severity TEXT,
                attack_class TEXT,
                mitre_id TEXT,
                s_iso REAL,
                s_lstm REAL,
                s_pred REAL,
                forecast_json TEXT,
                is_attack INTEGER DEFAULT 0
            )
        ''')
        conn.commit()
        conn.close()

    def get_state(self, device_id: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT trust_score, uts_history, attack_count, last_alert_time, acuity_level, status FROM threat_model_state WHERE device_id=?", (device_id,))
        row = c.fetchone()
        conn.close()
        
        if row is None:
            state = {
                'trust_score': 1.0,
                'uts_history': [],
                'attack_count': 0,
                'last_alert_time': None,
                'acuity_level': 0,
                'status': 'active'
            }
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("INSERT INTO threat_model_state (device_id, trust_score, uts_history, attack_count, last_alert_time, acuity_level, status) VALUES (?, 1.0, '[]', 0, NULL, 0, 'active')", (device_id,))
            conn.commit()
            conn.close()
            return state
            
        return {
            'trust_score': row[0],
            'uts_history': json.loads(row[1] if row[1] else '[]'),
            'attack_count': row[2],
            'last_alert_time': row[3],
            'acuity_level': row[4],
            'status': row[5]
        }

    def _update_state(self, device_id: str, diff: dict):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        updates = []
        params = []
        for k, v in diff.items():
            if k == 'uts_history':
                updates.append(f"{k}=?")
                params.append(json.dumps(v))
            else:
                updates.append(f"{k}=?")
                params.append(v)
                
        params.append(device_id)
        
        c.execute(f"UPDATE threat_model_state SET {', '.join(updates)} WHERE device_id=?", tuple(params))
        conn.commit()
        conn.close()

    def log_prediction(self, log_entry: dict):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO prediction_log (timestamp, device_id, uts, severity, attack_class, mitre_id, s_iso, s_lstm, s_pred, forecast_json, is_attack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (log_entry['timestamp'], log_entry['device_id'], log_entry['uts'], log_entry['severity'], 
              log_entry.get('attack_class'), log_entry.get('mitre_id'), log_entry['s_iso'], log_entry['s_lstm'], 
              log_entry['s_pred'], json.dumps(log_entry.get('forecast', [])), log_entry.get('is_attack', 0)))
        conn.commit()
        conn.close()

    def compute_uts(self, device_id: str, s_iso: float, s_lstm: float, s_pred: float, acuity_level: int = 0) -> dict:
        state = self.get_state(device_id)
        
        # S_iso scaled to [0,40], S_lstm scaled to [0,35], S_pred=0/25
        # Modifiers
        c_patient_map = {0: 0, 1: 5, 2: 10, 3: 15}
        c_patient = c_patient_map.get(acuity_level, 0)
        
        trust_score = state['trust_score']
        c_device = min(12.0, max(0.0, (1.0 - trust_score) * 12.0))
        
        m_history = 0.0
        uts_history = state['uts_history']
        for k, past_uts in enumerate(reversed(uts_history[-60:]), 1):
            m_history += past_uts * math.exp(-0.05 * k)
        m_history = min(20.0, max(0.0, 0.9 * m_history))
        
        uts = (self.w_iso * s_iso + self.w_lstm * s_lstm + self.w_pred * s_pred 
               + c_patient + c_device + m_history)
        uts = min(100.0, max(0.0, uts))
        
        if uts <= 20: severity, action = "NOMINAL", "none"
        elif uts <= 40: severity, action = "ADVISORY", "increase_sampling"
        elif uts <= 60: severity, action = "WARNING", "rate_limit"
        elif uts <= 80: severity, action = "THREAT", "suspend_30s"
        else: severity, action = "CRITICAL", "terminate_session"
        
        # update history
        uts_history.append(uts)
        if len(uts_history) > 60:
            uts_history.pop(0)
            
        self._update_state(device_id, {'uts_history': uts_history})
        
        return {
            'uts': float(uts),
            'severity': severity,
            'action': action,
            'trust_score': float(trust_score),
            'components': {
                's_iso': s_iso,
                's_lstm': s_lstm,
                's_pred': s_pred,
                'c_patient': c_patient,
                'c_device': c_device,
                'm_history': m_history
            }
        }

    def confirm_attack(self, device_id: str):
        state = self.get_state(device_id)
        new_trust = max(0.0, state['trust_score'] - self.dev_delta_attack)
        new_attack_count = state['attack_count'] + 1
        
        status = state['status']
        if new_trust < self.quarantine_thresh:
            status = 'quarantined'
            
        self._update_state(device_id, {
            'trust_score': new_trust,
            'attack_count': new_attack_count,
            'last_alert_time': datetime.utcnow().isoformat(),
            'status': status
        })

    def confirm_clean(self, device_id: str):
        state = self.get_state(device_id)
        new_trust = min(1.0, state['trust_score'] + self.dev_delta_clean)
        self._update_state(device_id, {'trust_score': new_trust})
