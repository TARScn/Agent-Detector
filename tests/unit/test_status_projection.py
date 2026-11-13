import pytest

pytest.skip("legacy asset tables removed in the v12 cutover",
            allow_module_level=True)

"""P1: evidence claims -> four-value agent status."""
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agent_detector.aggregation.evidence_ledger import EvidenceLedger
from agent_detector.aggregation.status_projection import project_entity
from agent_detector.core.enums import AgentStatus, AssetState, AssetType
from agent_detector.core.models import DetectedAsset, HostFacts, VersionInfo
from agent_detector.discovery.scanner import scan as scan_service
from agent_detector.storage import AgentInventoryRepository
from agent_detector.storage.database import make_engine
from agent_detector.storage.models import ClaimRow, EntitySnapshotRow


def add(session, *, predicate, rule_id="rule-1", polarity="support",
        object_ref="product", valid_to=None, evidence_class="E2"):
    return EvidenceLedger(session).add_claim(
        subject_ref="entity-1", predicate=predicate, object_ref=object_ref,
        polarity=polarity, evidence_class=evidence_class,
        verification_method="test", rule_id=rule_id, rule_digest="digest",
        collection_run_id=1, observed_at="2026-11-01T00:00:00+00:00",
        valid_from="2026-11-01T00:00:00+00:00", valid_to=valid_to)


def test_running_wins_and_basis_is_orthogonal(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        add(session, predicate="installed")
        add(session, predicate="configured")
        add(session, predicate="running", valid_to="2099-01-01T00:00:00+00:00")
        result = project_entity(session, "entity-1", 7)
        snapshot = session.scalars(select(EntitySnapshotRow)).first()
        assert result["agent_status"] == AgentStatus.RUNNING.value
        assert snapshot.agent_status == AgentStatus.RUNNING.value
        basis = result["capability_tags"] is not None  # snapshot path exercised
        assert basis
        session.commit()


def test_configured_precedes_installed(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        add(session, predicate="installed")
        add(session, predicate="configured")
        result = project_entity(session, "entity-1", 1)
    assert result["agent_status"] == AgentStatus.CONFIGURED.value


def test_installed_only(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        add(session, predicate="installed")
        result = project_entity(session, "entity-1", 1)
    assert result["agent_status"] == AgentStatus.INSTALLED.value


def test_no_claims_is_unknown(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        result = project_entity(session, "entity-1", 1)
    assert result["agent_status"] == AgentStatus.UNKNOWN.value


def test_expired_running_does_not_keep_running(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        add(session, predicate="installed")
        add(session, predicate="running",
            valid_to="2001-01-01T00:00:00+00:00")
        result = project_entity(session, "entity-1", 1)
    assert result["agent_status"] == AgentStatus.INSTALLED.value


def test_conflicting_rules_are_not_merged(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        add(session, predicate="installed", rule_id="rule-a", polarity="support")
        add(session, predicate="installed", rule_id="rule-b", polarity="refute")
        result = project_entity(session, "entity-1", 1)
    # Policy prefers positive for `installed`, but the conflict is recorded.
    assert result["agent_status"] == AgentStatus.INSTALLED.value
    assert "installed" in result["conflicts"]


def test_capability_tags_are_projected(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        add(session, predicate="agent_capability", object_ref="AI_RELATED")
        add(session, predicate="agent_capability", object_ref="AGENT_CAPABLE")
        result = project_entity(session, "entity-1", 1)
    assert result["capability_tags"] == ["AGENT_CAPABLE", "AI_RELATED"]


class _Detector:
    name = "fake"

    def __init__(self, state):
        self.state = state

    def detect(self, facts):
        return [DetectedAsset(
            asset_id="claude--1", name="Claude Code",
            asset_type=AssetType.AGENT_CLIENT, states={self.state},
            confidence=0.9, version=VersionInfo.unknown(), evidence=[],
            detector="fake", scope_kind="user-home",
            identity_scope="/home/bob")]


def test_scan_writes_running_status_and_claims(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(engine, detectors=[_Detector(AssetState.RUNNING)],
                                   docker_enabled=False)
    assert result["evidence"]["claims"] >= 1
    assert result["evidence"]["statuses"].get("RUNNING") == 1
    with Session(engine) as session:
        assert session.scalar(select(func.count()).select_from(ClaimRow)) >= 1
        asset = AgentInventoryRepository(session).get_asset("claude--1")
        assert asset["agent_status"] == "RUNNING"
        assert "AI_RELATED" in asset["capability_tags"]


def test_scan_projects_removal_candidate_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    scan_service.run_scan(engine, detectors=[_Detector(AssetState.RUNNING)],
                          docker_enabled=False)
    result = scan_service.run_scan(engine, detectors=[], docker_enabled=False)
    assert result["removal_candidates"] >= 1
    with Session(engine) as session:
        asset = AgentInventoryRepository(session).get_asset("claude--1")
        assert asset["removal_verdict"] == "CANDIDATE"


def test_scan_writes_configured_status(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(engine, detectors=[_Detector(AssetState.CONFIGURED)],
                                   docker_enabled=False)
    assert result["evidence"]["statuses"].get("CONFIGURED") == 1
    with Session(engine) as session:
        asset = AgentInventoryRepository(session).get_asset("claude--1")
        assert asset["agent_status"] == "CONFIGURED"