import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agent_detector.application.scan_service import run_scan
from agent_detector.common.config import DB_PATH, MAX_PROBES
from agent_detector.fingerprints.loader import load_rules
from agent_detector.gateway.manager import GatewayError, GatewayManager
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.repositories import (AssetRepository, BehaviorEventRepository,
                                                     EvidenceRepository, ScanRepository)

app = FastAPI(title="Agent Detector", version="0.1.0")
engine = make_engine(DB_PATH)
scan_lock = threading.Lock()
gateway_manager = GatewayManager(db_path=DB_PATH)


class ScanRequest(BaseModel):
    active: bool = False


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


@app.get("/api/gateway/status")
def gateway_status():
    return gateway_manager.status()


@app.post("/api/gateway/start")
def gateway_start():
    try:
        return gateway_manager.start()
    except GatewayError as exc:
        message = str(exc)
        code = 409 if "already running" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.post("/api/gateway/stop")
def gateway_stop():
    try:
        return gateway_manager.stop()
    except GatewayError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/gateway/events")
def gateway_events(limit: int = 100, protocol: str | None = None):
    if protocol and protocol not in {"LLM", "MCP", "A2A"}:
        return {"items": []}
    with Session(engine) as session:
        return {"items": BehaviorEventRepository(session).list_events(limit=limit,
                                                                      protocol=protocol)}


@app.get("/api/gateway/stats")
def gateway_stats():
    with Session(engine) as session:
        return BehaviorEventRepository(session).stats()
