"""Repositories: the only entry point for database access (plan section 5.1)."""
from agent_detector.persistence.repositories.asset_repository import AssetRepository
from agent_detector.persistence.repositories.evidence_repository import EvidenceRepository
from agent_detector.persistence.repositories.scan_repository import ScanRepository

__all__ = ["AssetRepository", "EvidenceRepository", "ScanRepository"]
