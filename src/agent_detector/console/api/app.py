"""FastAPI application: console API + static console + internal hook API (§2).

Route layout:

* ``/api/v1/...``        console API (read-mostly, JSON)
* ``/internal/v1/...``   synchronous hook decision API (token protected)
* ``/``                  the Vue-free console shell (``web/`` static assets)

The console is served from the same process as the API so a single
``uvicorn agent_detector.console.api.app:app`` is all a user needs (design section 2).
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from agent_detector import __version__
from agent_detector.console.api.deps import get_services
from agent_detector.console.api import (agents, alerts, discovery, events, hooks, internal,
                                        policies, system, telemetry)

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


def create_app(*, serve_console: bool = True) -> FastAPI:
    app = FastAPI(title="Agent Detector", version=__version__,
                  description="本机 AI Agent 资产发现、行为监测与执行前拦截")
    app.include_router(system.router)
    app.include_router(agents.router)
    app.include_router(discovery.router)
    app.include_router(events.router)
    app.include_router(policies.router)
    app.include_router(alerts.router)
    app.include_router(telemetry.router)
    app.include_router(hooks.router)
    app.include_router(internal.router)

    @app.get("/api/health", tags=["system"])
    def health():
        """Liveness probe (kept unversioned: it answers before any model loads)."""
        return {"status": "ok", "version": app.version}

    @app.get("/api/v1/capabilities", tags=["system"])
    def capabilities():
        """Which modes this build supports, and which of them are wired yet."""
        return {"version": app.version, "modes": {
            "discovery": {"implemented": True},
            "monitor": {"implemented": True, "channels": {
                "native_hook": True, "sysmon": True, "auditd": True,
                "poll": True, "netmon": True}},
            "protect": {"implemented": True, "agents": ["claude_code", "codex_cli",
                                                        "cursor"],
                        "not_implemented": ["gemini_cli", "opencode",
                                            "github_copilot_cli"]}}}

    if serve_console and WEB_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="console")

        @app.middleware("http")
        async def _revalidate_console(request, call_next):
            # 控制台静态资源永远重验证（配合 etag 只是廉价的 304）：
            # 没有这个头，浏览器会对 JS 做启发式缓存，前端改完用户看到的还是旧界面。
            response = await call_next(request)
            path = request.url.path
            if not path.startswith("/api") and not path.startswith("/internal"):
                response.headers["Cache-Control"] = "no-cache"
            return response

    @app.exception_handler(RuntimeError)
    def _runtime_error(_request, exc: RuntimeError):
        logger.exception("unhandled runtime error")
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    return app


app = create_app()


def main() -> None:  # pragma: no cover - convenience entry point
    """``python -m agent_detector.console.api.app`` — dev server on loopback."""
    import uvicorn

    from agent_detector.core.config import WEB_HOST, WEB_PORT

    get_services()
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT)


if __name__ == "__main__":  # pragma: no cover
    main()