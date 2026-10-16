from agent_detector.application import scan_service
from agent_detector.domain.enums import AssetState, AssetType
from agent_detector.domain.models import DetectedAsset, HostFacts, VersionInfo
from agent_detector.persistence.database import make_engine


class GoodDetector:
    name = "good"

    def __init__(self, asset):
        self.asset = asset

    def detect(self, facts):
        return [self.asset]


class BrokenDetector:
    name = "broken"

    def detect(self, facts):
        raise RuntimeError("boom")


def make_asset(asset_id="x--1"):
    return DetectedAsset(asset_id=asset_id, name="X", asset_type=AssetType.AGENT_CLIENT,
                         states={AssetState.RUNNING}, confidence=0.7,
                         version=VersionInfo.unknown(), evidence=[], detector="good")


def test_run_scan_isolates_detector_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_service, "collect_host_facts",
                        lambda: HostFacts("h", (), ()))
    engine = make_engine(tmp_path / "db.sqlite3")
    result = scan_service.run_scan(
        engine, detectors=[GoodDetector(make_asset()), BrokenDetector()])
    assert result["status"] == "completed"
    assert result["assets"] == 1
    assert result["errors"] == [{"detector": "broken", "error": "boom"}]
    assert result["asset_summaries"][0]["asset_id"] == "x--1"


def test_merge_assets_combines_states_and_keeps_evidence():
    first = make_asset("x--1")
    first.states = {AssetState.RUNNING}
    second = make_asset("x--1")
    second.states = {AssetState.INSTALLED, AssetState.CONFIGURED}
    second.confidence = 0.95
    (merged,) = scan_service.merge_assets([first, second])
    assert merged.states == {AssetState.RUNNING, AssetState.INSTALLED, AssetState.CONFIGURED}
    assert merged.confidence == 0.95
