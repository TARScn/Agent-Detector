"""Controlled runtime / protocol trace adapters (P2)."""

from agent_detector.monitoring.collectors.trace.controlled import (
    TraceEvent, read_trace)

__all__ = ["TraceEvent", "read_trace"]