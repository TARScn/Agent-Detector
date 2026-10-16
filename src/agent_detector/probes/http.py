import ipaddress
import json
import httpx
from agent_detector.models import Finding, Observation

PATHS = ("/health", "/openapi.json", "/")
HEADERS = {"User-Agent": "AgentDetector/0.1", "Accept": "application/json, text/plain, */*"}


def is_local(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback or ipaddress.ip_address(host.split("%")[0]).is_unspecified
    except ValueError:
        return False


def probe(observations: list[Observation], max_probes: int = 20) -> list[Finding]:
    """Only probes LISTEN endpoints reported locally; no redirects / remote traversal."""
    ports = sorted({o.port for o in observations if o.kind == "listen" and o.port and o.host and is_local(o.host)})
    findings: list[Finding] = []
    with httpx.Client(timeout=0.6, follow_redirects=False, trust_env=False) as client:
        for port in ports[:max_probes]:
            for path in PATHS:
                try:
                    r = client.get(f"http://127.0.0.1:{port}{path}", headers=HEADERS)
                    body = r.text[:2048].lower()
                    server = r.headers.get("server", "")[:160]
                    description = (body + " " + server).lower()
                    tokens = [("Ollama", "model-server", "ollama"), ("vLLM", "model-server", "vllm"),
                              ("Open WebUI", "ai-application", "open webui"),
                              ("FastMCP", "mcp", "fastmcp"), ("Dify", "agent-platform", "dify")]
                    for name, category, needle in tokens:
                        if needle not in description:
                            continue
                        findings.append(Finding(
                            component=name, category=category, confidence=0.75, state="http-responsive",
                            port=port, evidence=[{"kind": "http", "value": f"127.0.0.1:{port}{path}",
                                                  "status": r.status_code, "server": server,
                                                  "matched": needle}],
                        ))
                    # Successful HTTP handshake is enough; don't send more requests to the same port.
                    if r.status_code < 500:
                        break
                except (httpx.TimeoutException, httpx.RequestError, UnicodeError):
                    break
    return findings
