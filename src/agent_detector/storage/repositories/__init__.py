"""Repositories: the only entry point for database access (design section 2)."""
from agent_detector.storage.repositories.agent_repository import AgentInventoryRepository
from agent_detector.storage.repositories.alert_repository import AlertRepository
from agent_detector.storage.repositories.asset_repository import AssetRepository
from agent_detector.storage.repositories.behavior_event_repository import BehaviorEventRepository
from agent_detector.storage.repositories.evidence_repository import EvidenceRepository
from agent_detector.storage.repositories.policy_repository import PolicyRepository
from agent_detector.storage.repositories.scan_repository import ScanRepository

__all__ = [
    "AgentInventoryRepository",
    "AlertRepository",
    "AssetRepository",
    "BehaviorEventRepository",
    "EvidenceRepository",
    "PolicyRepository",
    "ScanRepository",
]