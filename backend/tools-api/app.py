from fastapi import FastAPI
from datetime import datetime

app = FastAPI(title="RomanoTI Tools API", version="0.1")

@app.get("/health")
def health():
    return {"status": "ok", "service": "romanoti-tools", "ts": datetime.utcnow().isoformat()}

