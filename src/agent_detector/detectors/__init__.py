"""Detector registry: new agents plug in here, never in the scan service."""
from agent_detector.detectors.agent_clients.claude_code import ClaudeCodeDetector
from agent_detector.detectors.registry import Detector
from agent_detector.detectors.signatures import SignatureDetector


def build_detectors() -> list[Detector]:
    return [SignatureDetector(), ClaudeCodeDetector()]

