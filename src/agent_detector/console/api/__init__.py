"""HTTP layer: console API (/api/v1), internal hook API (/internal/v1), console."""

from agent_detector.console.api.app import create_app

__all__ = ["create_app"]
