import os
import torch
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from model import HybridLSTMAE

app = FastAPI(title="LSTM Inference Service")

MODEL_PATH = os.getenv("MODEL_PATH", "lstm_ae.pt")
NORM_STATS_PATH = os.getenv("NORM_STATS_PATH", "norm_stats.json")

model = HybridLSTMAE()
if os.path.exists(MODEL_PATH):
    model.load_state_dict(torch.load(MODEL_PATH, map_location='cpu'))
model.eval()

class ProbeRequest(BaseModel):
    device_id: str
    eps: float
    window: List[List[float]]

@app.post("/anomaly_score")
def get_anomaly_score(payload: dict):
    window_data = payload.get("window")
    device_id = payload.get("device_id")
    x = torch.tensor(window_data, dtype=torch.float32).unsqueeze(0)
    # The adaptive threshold logic is simple here, assume a global threshold or rolling
    if len(model.clean_scores) < 10:
        threshold = 0.5
    else:
        threshold = sorted(list(model.clean_scores))[int(0.95 * len(model.clean_scores))]
        
    result = model.anomaly_score(x, threshold, device_id, norm_stats_path=NORM_STATS_PATH)
    
    if not result['is_anomaly']:
        model.clean_scores.append(result['mse'])
        
    return result

@app.post("/adversarial-probe")
def adversarial_probe(payload: ProbeRequest):
    # dynamic import so we don't break if not available
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    try:
        from adversarial_evaluator import AdversarialEvaluator
    except ImportError:
        raise HTTPException(status_code=500, detail="Adversarial Evaluator not found")
        
    evaluator = AdversarialEvaluator(model)
    report = evaluator.evaluate(payload.window, eps=payload.eps)
    return report

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
