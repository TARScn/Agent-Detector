import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agent_detector.application.scan_service import run_scan
from agent_detector.common.config import DB_PATH
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.repositories import (AssetRepository, EvidenceRepository,
                                                     ScanRepository)

app = FastAPI(title="Agent Detector", version="0.1.0")
engine = make_engine(DB_PATH)
scan_lock = threading.Lock()


class ScanRequest(BaseModel):
    active: bool = False


@app.get("/", response_class=HTMLResponse)
def homepage():
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.post("/api/scans")
def create_scan(body: ScanRequest):
    if not scan_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="Scan already running")
    try:
        return run_scan(engine, active=body.active)
    finally:
        scan_lock.release()


@app.get("/api/scans")
def list_scans():
    with Session(engine) as session:
        return ScanRepository(session).list()


@app.get("/api/assets")
def list_assets(scan_id: int | None = None):
    with Session(engine) as session:
        repo = AssetRepository(session)
        if scan_id is not None:
            return repo.list_snapshots(scan_id)
        return repo.latest_snapshots()


@app.get("/api/assets/{asset_id}/evidence")
def asset_evidence(asset_id: str, scan_id: int | None = None):
    with Session(engine) as session:
        evidence = EvidenceRepository(session).for_asset(asset_id, scan_id=scan_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="No evidence recorded for this asset")
    return evidence
