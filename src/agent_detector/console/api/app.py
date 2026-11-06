"""FastAPI application: console API + static console + internal hook API (§2).

Route layout:

* ``/api/v1/...``        console API (read-mostly, JSON)
* ``/internal/v1/...``   synchronous hook decision API (token protected)
* ``/``                  the console shell (``web/next`` React build, legacy fallback)

The console is served from the same process as the API so a single
``uvicorn agent_detector.console.api.app:app`` is all a user needs (design section 2).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from agent_detector import __version__
from agent_detector.console.api.deps import get_services
from agent_detector.console.api import (agents, alerts, attention, discovery, events,
                                        evidence, hooks, internal, policies, system,
                                        telemetry)

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
NEXT_DIR = WEB_DIR / "next"


def console_root() -> Path:
    """Select the built React console, falling back to the legacy shell.

    ``CONSOLE_UI=legacy|next`` forces a variant; otherwise the React build is
    used when present. This keeps one rollback switch without mounting two
    consoles at ``/``.
    """
    choice = os.getenv("CONSOLE_UI", "").strip().lower()
    if choice == "legacy":
        return WEB_DIR
    if choice == "next":
        return NEXT_DIR
    return NEXT_DIR if (NEXT_DIR / "index.html").is_file() else WEB_DIR


def create_app(*, serve_console: bool = True) -> FastAPI:
    app = FastAPI(title="Agent Detector", version=__version__,
                  description="本机 AI Agent 资产发现、行为监测与执行前拦截")
    app.include_router(system.router)
    app.include_router(agents.router)
    app.include_router(discovery.router)
    app.include_router(events.router)
    app.include_router(attention.router)
    app.include_router(evidence.router)
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
                "tetragon": True, "poll": True, "netmon": True}},
            "protect": {"implemented": True, "agents": ["claude_code", "codex_cli",
                                                        "cursor"],
                        "not_implemented": ["gemini_cli", "opencode",
                                            "github_copilot_cli"]}}}

    root = console_root()
    if serve_console and root.is_dir():
        app.mount("/", StaticFiles(directory=str(root), html=True), name="console")

        @app.middleware("http")
        async def _revalidate_console(request, call_next):
            # index.html must revalidate (a stale shell hides a new build);
            # Vite's content-hashed assets can be cached immutably.
            response = await call_next(request)
            path = request.url.path
            if not path.startswith("/api") and not path.startswith("/internal"):
                if root == NEXT_DIR and path.startswith("/assets/"):
                    response.headers["Cache-Control"] = (
                        "public, max-age=31536000, immutable")
                else:
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