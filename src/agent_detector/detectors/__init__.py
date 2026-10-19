"""Detectors are assembled from declarative YAML rules (fingerprints/rules/).

Adding detection targets means editing rule data — a new client rule file in
the rules directory (or an AGENT_DETECTOR_RULES_DIR override) — never touching
the scan service or this module.
"""
from agent_detector.detectors.registry import Detector
from agent_detector.fingerprints.engine import ClientRuleDetector, SignatureRuleDetector
from agent_detector.fingerprints.loader import load_rules


def build_detectors() -> list[Detector]:
    loaded = load_rules()
    detectors: list[Detector] = [SignatureRuleDetector(loaded.signature_rules)]
    detectors.extend(ClientRuleDetector(rule) for rule in loaded.client_rules)
    return detectors
