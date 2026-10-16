"""Detector contract (plan section 8.3): host facts in, candidate assets out."""
import re
from typing import Protocol, runtime_checkable

from agent_detector.domain.models import DetectedAsset, HostFacts


@runtime_checkable
class Detector(Protocol):
    name: str

    def detect(self, facts: HostFacts) -> list[DetectedAsset]: ...


def slugify(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return cleaned or "unknown"
