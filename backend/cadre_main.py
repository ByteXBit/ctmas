import os
from fastapi import FastAPI
from pydantic import BaseModel
from cadre import CADRE

app = FastAPI(title="CADRE Risk Engine")

db_path = os.getenv("DB_PATH", "medical_cps.db")
cadre = CADRE(db_path=db_path)

class ComputeReq(BaseModel):
    device_id: str
    s_iso: float
    s_lstm: float
    s_pred: float
    acuity_level: int = 0
    
class ConfirmReq(BaseModel):
    device_id: str

@app.post("/compute_uts")
def compute_uts(payload: dict):
    return cadre.compute_uts(
        payload["device_id"],
        payload["s_iso"],
        payload["s_lstm"],
        payload["s_pred"],
        payload.get("acuity_level", 0)
    )

@app.post("/confirm_attack")
def confirm_attack(payload: ConfirmReq):
    cadre.confirm_attack(payload.device_id)
    return {"status": "success"}

@app.post("/confirm_clean")
def confirm_clean(payload: ConfirmReq):
    cadre.confirm_clean(payload.device_id)
    return {"status": "success"}

@app.get("/state/{device_id}")
def get_state(device_id: str):
    return cadre.get_state(device_id)
    
@app.post("/log_prediction")
def log_prediction(payload: dict):
    cadre.log_prediction(payload)
    return {"status": "success"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
