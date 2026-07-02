from fastapi import FastAPI
from backend.app.routers.candidates import router as candidates_router

app = FastAPI(title="AI Pentester", version="0.1.0")
app.include_router(candidates_router)


@app.get("/health")
def health():
    return {"status": "ok"}
