import time
import requests
import random
import math
from datetime import datetime

# Configuration
API_URL = "http://localhost:8000/predict"
DEVICE_ID = "server_node_01"
SLEEP_TIME = 2.0

def generate_ecg(t, is_noisy=False, is_flat=False):
    if is_flat:
        return [0.0] * 250
        
    signal = []
    for i in range(250):
        # Extremely simplified synthetic ECG
        cycle = (t + i) % 100
        val = 0
        if cycle == 10: val = 0.5
        elif cycle == 30: val = -0.5
        elif cycle == 32: val = 2.5
        elif cycle == 35: val = -1.0
        elif cycle == 60: val = 0.7
        else: val = (random.random() - 0.5) * 0.1
        
        if is_noisy:
            val += (random.random() - 0.5) * 5.0 # Huge noise
            
        signal.append(val)
    return signal

def simulate_streaming():
    print(f"Starting Medical CPS Threat Simulation for device: {DEVICE_ID}")
    
    t = 0
    while True:
        # Generate normal baseline traffic
        current_device_id = DEVICE_ID
        is_noisy_ecg = False
        is_flat_ecg = False
        heart_rate = random.gauss(80, 5)
        
        # Inject random anomalies (10% chance)
        if random.random() < 0.10:
            attack_type = random.choice(["data_injection", "dos", "spoofing"])
            if attack_type == "data_injection":
                is_noisy_ecg = True
                heart_rate = 250.0
                print(f"[!] INJECTING: False Data Injection (Tampering)")
            elif attack_type == "dos":
                is_flat_ecg = True
                heart_rate = 0.0
                print(f"[!] INJECTING: Denial of Service (Sensor Offline)")
            elif attack_type == "spoofing":
                current_device_id = "unknown_hacker_node"
                print(f"[!] INJECTING: Device Spoofing Attack")
                
        ecg_window = generate_ecg(t, is_noisy_ecg, is_flat_ecg)
        t += 250
                
        payload = {
            "timestamp": datetime.now().isoformat(),
            "device_id": current_device_id,
            "ecg_signal": ecg_window,
            "heart_rate": max(heart_rate, 0.0)
        }
        
        try:
            res = requests.post(API_URL, json=payload)
            if res.status_code == 200:
                data = res.json()
                print(f"Sent Telemetry. Threat: {data['threat_type']}, Risk Score: {data['risk_score']:.2f}")
            else:
                print(f"Server error: {res.status_code}")
        except Exception as e:
            print(f"Failed to connect to API: {e}")
            
        time.sleep(SLEEP_TIME)

if __name__ == "__main__":
    simulate_streaming()
