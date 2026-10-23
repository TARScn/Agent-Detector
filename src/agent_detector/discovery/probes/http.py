"""Active HTTP fingerprint probing of already-observed local listeners.

Behavior kept from V0.1: loopback-only, no redirects, no proxy env, short
timeouts, bounded request count. Only produces evidence, never executes tools.
"""
import ipaddress

import httpx

from agent_detector.core.enums import AssetState, AssetType, EvidenceKind
from agent_detector.core.models import DetectedAsset, Evidence, HostFacts, VersionInfo
from agent_detector.core.identity import build_asset_id, slugify

PATHS = ("/health", "/openapi.json", "/")
HEADERS = {"User-Agent": "AgentDetector/0.1", "Accept": "application/json, text/plain, */*"}
TOKENS = [
    ("Ollama", AssetType.LLM_SERVICE, "ollama"),
    ("vLLM", AssetType.LLM_SERVICE, "vllm"),
    ("Open WebUI", AssetType.AI_APPLICATION, "open webui"),
    ("FastMCP", AssetType.MCP_SERVER, "fastmcp"),
    ("Dify", AssetType.AGENT_PLATFORM, "dify"),
]


def is_local(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host.split("%")[0])
        return address.is_loopback or address.is_unspecified
    except ValueError:
        return False


def probe_facts(facts: HostFacts, max_probes: int = 20) -> list[DetectedAsset]:
    """Only probes LISTEN endpoints reported locally; no redirects / remote traversal."""
    ports = sorted({s.port for s in facts.sockets if s.port and s.host and is_local(s.host)})
    assets: list[DetectedAsset] = []
    with httpx.Client(timeout=0.6, follow_redirects=False, trust_env=False) as client:
        for port in ports[:max_probes]:
            for path in PATHS:
                try:
                    response = client.get(f"http://127.0.0.1:{port}{path}", headers=HEADERS)
                    body = response.text[:2048].lower()
                    server = response.headers.get("server", "")[:160]
                    description = body + " " + server.lower()
                    for name, asset_type, needle in TOKENS:
                        if needle not in description:
                            continue
                        url = f"127.0.0.1:{port}{path}"
                        assets.append(DetectedAsset(
                            asset_id=build_asset_id(facts.hostname, slugify(name),
                                                    f"listen-port:{port}"),
                            name=name, asset_type=asset_type,
                            states={AssetState.RUNNING}, confidence=0.75,
                            version=VersionInfo.unknown(),
                            evidence=[Evidence(EvidenceKind.HTTP_PROBE,
                                               f"{url} responded with '{needle}' fingerprint",
                                               {"url": url, "status": response.status_code,
                                                "server": server, "matched": needle}, 0.75)],
                            listening_ports=[port], detector="http-probe"))
                    # Successful HTTP handshake is enough; don't send more requests.
                    if response.status_code < 500:
                        break
                except (httpx.TimeoutException, httpx.RequestError, UnicodeError):
                    break
    return assets
