"""Agent Detector hook bridge (stdlib only).

Runs inside the Agent's tool-call path: reads the hook payload from stdin,
asks the local decision service, prints the platform's answer. Install it via
``agent-detector hooks install --apply`` rather than by hand.
"""
__all__ = ["entry", "transport"]