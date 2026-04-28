from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routers import router
from app.db.models import init_db

app = FastAPI(title="Adaptive Cardiac Monitoring System API")

# Setup CORS for Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db()

app.include_router(router)

from api_extensions import router as ext_router
app.include_router(ext_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
