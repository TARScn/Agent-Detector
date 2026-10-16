from agent_detector.collectors.linux import collect
from agent_detector.detectors.signatures import detect
from agent_detector.probes.http import probe
from agent_detector.storage.sqlite import Store
from agent_detector.config import MAX_PROBES


def run_scan(store: Store, active: bool = False) -> dict:
    observations = collect()
    findings = detect(observations)
    if active:
        findings.extend(probe(observations, MAX_PROBES))
    # Merge repeated component/port/pid matches while retaining all evidence.
    merged = {}
    for f in findings:
        key = (f.component, f.pid, f.port)
        if key not in merged:
            merged[key] = f
        else:
            prior = merged[key]
            prior.confidence = max(prior.confidence, f.confidence)
            prior.evidence.extend(f.evidence)
    results = list(merged.values())
    scan_id = store.save(active, len(observations), results)
    return {"scan_id": scan_id, "mode": "active+passive" if active else "passive",
            "observations": len(observations), "findings": len(results)}
