import re
from dataclasses import dataclass
from agent_detector.models import Finding, Observation


@dataclass(frozen=True)
class Signature:
    name: str
    category: str
    expression: str


# Conservative patterns: match an executable / module / recognizable token,
# not general words such as 'agent' or 'python'.
SIGNATURES = [
    Signature("Ollama", "model-server", r"(?<![\w-])ollama(?:\s+serve)?(?![\w-])"),
    Signature("vLLM", "model-server", r"(?:\bvllm\b|vllm\.entrypoints)"),
    Signature("LM Studio", "model-server", r"\blmstudio\b|\blm-studio\b"),
    Signature("Open WebUI", "ai-application", r"\bopen-webui\b|\bopen_webui\b"),
    Signature("Dify", "agent-platform", r"(?:\bdify\b|\bdify-api\b)"),
    Signature("LangGraph", "agent-framework", r"\blanggraph\b"),
    Signature("LangChain", "agent-framework", r"\blangchain\b"),
    Signature("AutoGen", "agent-framework", r"\bautogen(?:_agentchat|_studio)?\b"),
    Signature("CrewAI", "agent-framework", r"\bcrewai\b"),
    Signature("AgentScope", "agent-framework", r"\bagentscope\b"),
    Signature("MCP Server", "mcp", r"\bmcp[-_ ]server\b|\bmcp\.server\b|\bfastmcp\b"),
    Signature("Claude Code", "agent-tool", r"\bclaude(?:-code)?\b"),
    Signature("Codex CLI", "agent-tool", r"\bcodex(?:-cli)?\b"),
    Signature("OpenClaw", "agent-tool", r"\bopenclaw\b"),
]
VERSION_RE = re.compile(r"(?<!\w)(?:--version[= ]|version[= ]|\bv)(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)", re.I)


def detect(observations: list[Observation]) -> list[Finding]:
    by_pid: dict[int, list[Observation]] = {}
    for o in observations:
        if o.pid is not None:
            by_pid.setdefault(o.pid, []).append(o)
    findings: list[Finding] = []
    for o in observations:
        if o.kind != "process":
            continue
        for sig in SIGNATURES:
            if not re.search(sig.expression, o.value, re.I):
                continue
            related = [x for x in by_pid.get(o.pid, []) if x.kind == "listen"]
            match = VERSION_RE.search(o.value)
            findings.append(Finding(
                component=sig.name, category=sig.category, confidence=0.85 if related else 0.65,
                state="listening" if related else "running",
                pid=o.pid, port=related[0].port if related else None,
                version=match.group(1) if match else None,
                version_source="process-claim" if match else None,
                evidence=[o.to_dict()] + [x.to_dict() for x in related],
            ))
    return findings
