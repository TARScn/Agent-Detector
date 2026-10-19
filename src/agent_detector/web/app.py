import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agent_detector.application.scan_service import run_scan
from agent_detector.behavior.monitor_service import MonitorError, MonitorManager
from agent_detector.common.config import DB_PATH, MAX_PROBES
from agent_detector.fingerprints.loader import load_rules
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.repositories import (AssetRepository, BehaviorEventRepository,
                                                     EvidenceRepository, ScanRepository)

app = FastAPI(title="Agent Detector", version="0.1.0")
engine = make_engine(DB_PATH)
scan_lock = threading.Lock()
monitor_manager = MonitorManager(engine)


class ScanRequest(BaseModel):
    active: bool = False


class MonitorRequest(BaseModel):
    interval: float | None = None
    suppress_seconds: int | None = None


@app.get("/", response_class=HTMLResponse)
def homepage():
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/api/settings")
def get_settings():
    return {"version": app.version, "db_path": str(DB_PATH), "max_probes": MAX_PROBES,
            "listen": "127.0.0.1"}


@app.get("/api/rules")
def list_rules():
    loaded = load_rules()
    return {
        "client_rules": [
            {"id": rule.id, "name": rule.name, "asset_type": rule.asset_type.value,
             "revision": rule.revision,
             "install_probes": (len(rule.install.npm_packages) + len(rule.install.paths)
                                + len(rule.install.dirs)),
             "config_probes": (len(rule.config.json_files)
                               + len(rule.config.existing_files)),
             "version_steps": len(rule.version),
             "has_process_match": rule.process is not None}
            for rule in loaded.client_rules],
        "signature_rules": [
            {"name": rule.name, "asset_type": rule.asset_type.value,
             "pattern": rule.pattern}
            for rule in loaded.signature_rules],
        "errors": [{"file": error.file, "error": error.error} for error in loaded.errors],
    }


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


@app.get("/api/monitor/status")
def monitor_status():
    return monitor_manager.status()


@app.post("/api/monitor/start")
def monitor_start(body: MonitorRequest | None = None):
    try:
        return monitor_manager.start(
            interval=body.interval if body else None,
            suppress_seconds=body.suppress_seconds if body else None)
    except MonitorError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/monitor/stop")
def monitor_stop():
    return monitor_manager.stop()


@app.get("/api/monitor/events")
def monitor_events(limit: int = 100):
    with Session(engine) as session:
        return {"items": BehaviorEventRepository(session).list_events(limit=limit,
                                                                      source="netmon")}


@app.get("/api/monitor/stats")
def monitor_stats():
    with Session(engine) as session:
        return BehaviorEventRepository(session).stats(source="netmon")
