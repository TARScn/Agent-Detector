"""Readers for the Tetragon JSON export file.

The export is a plain growing JSON-lines file with size-based rotation, so the
audit channel's tail/replay mechanics apply unchanged: EOF-following with
inode-based rotation detection (TailReader) and one-shot full reads
(ReplayReader). They are re-exported here to keep the eBPF package self-named
without duplicating the implementation.
"""
from agent_detector.monitoring.collectors.audit.reader import ReplayReader, TailReader

__all__ = ["ReplayReader", "TailReader"]
