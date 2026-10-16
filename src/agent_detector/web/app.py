import asyncio
import threading
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from agent_detector.config import DB_PATH
from agent_detector.service import run_scan
from agent_detector.storage.sqlite import Store

app = FastAPI(title="Agent Detector", version="0.1.0")
store = Store(DB_PATH)
scan_lock = threading.Lock()


class ScanRequest(BaseModel):
    active: bool = False


@app.get("/", response_class=HTMLResponse)
def homepage():
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/api/scans")
def create_scan(body: ScanRequest):
    if not scan_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Scan already running")
    try:
        return run_scan(store, body.active)
    finally:
        scan_lock.release()


@app.get("/api/scans")
def list_scans():
    return store.scans()


@app.get("/api/findings")
def list_findings(scan_id: int | None = None):
    return store.findings(scan_id=scan_id)
