"""executable_version_flag probing: gated on passive install evidence,
fixed argv from rule data, no shell, version taken from the first regex match."""
import sys

from agent_detector.core.enums import EvidenceKind
from agent_detector.core.models import HostFacts
from agent_detector.discovery.fingerprints.engine import ClientRuleDetector
from agent_detector.discovery.fingerprints.schema import ClientRule


def make_rule(install_path: str, **version_step) -> ClientRule:
    """Passive evidence probes install_path; the version step is independent."""
    step = {"from": "executable_version_flag", "timeout_ms": 5000,
            "source": "installer-metadata", "confidence": 0.85, **version_step}
    return ClientRule.model_validate({
        "kind": "client_rule", "id": "probe-test", "name": "Probe Test",
        "asset_type": "AGENT_CLIENT",
        "install": {"paths": [{"path": install_path, "confidence": 0.85}]},
        "version": [step],
    })


def python_probe_rule(marker: str | None = None, install_path: str | None = None):
    """A rule whose probe target is this interpreter running a tiny script."""
    body = "print('probe v9.9.9 ok')"
    if marker:
        body = f"open({str(marker)!r}, 'w').write('ran');{body}"
    return make_rule(install_path=install_path or sys.executable,
                     path=sys.executable, argv=["-c", body],
                     pattern=r"v(\d+\.\d+\.\d+)")


def test_version_probe_runs_and_parses_when_installed(tmp_path):
    marker = tmp_path / "marker.txt"
    detector = ClientRuleDetector(python_probe_rule(marker=str(marker)))
    assets = detector.detect(HostFacts("h", (), ()))
    assert len(assets) == 1
    asset = assets[0]
    assert asset.version.value == "9.9.9"
    assert asset.version.source.value == "installer-metadata"
    assert any(e.kind is EvidenceKind.INSTALL_METADATA for e in asset.evidence)
    assert marker.read_text(encoding="utf-8") == "ran"


def test_version_probe_never_runs_without_install_evidence(tmp_path):
    """No passive evidence -> the detector bails before executing anything."""
    marker = tmp_path / "marker.txt"
    missing = str(tmp_path / "missing.exe")
    detector = ClientRuleDetector(python_probe_rule(marker=str(marker),
                                                    install_path=missing))
    assert detector.detect(HostFacts("h", (), ())) == []
    assert not marker.exists()


def test_unparsable_version_output_stays_unknown():
    rule = make_rule(install_path=sys.executable, path=sys.executable,
                     argv=["-c", "print('no version here')"],
                     pattern=r"v(\d+\.\d+\.\d+)")
    detector = ClientRuleDetector(rule)
    assets = detector.detect(HostFacts("h", (), ()))
    assert len(assets) == 1
    assert assets[0].version.value == "UNKNOWN"
