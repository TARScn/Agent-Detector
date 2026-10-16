"""Generic command-line signature detection over collected host facts."""
import re
from dataclasses import dataclass

from agent_detector.common.security import redact
from agent_detector.domain.enums import AssetState, AssetType, EvidenceKind, VersionSource
from agent_detector.domain.models import (DetectedAsset, Evidence, HostFacts, ProcessInfo,
                                          VersionInfo)
from agent_detector.recognition.identity import build_asset_id, normalize_path
from agent_detector.detectors.registry import slugify

_CMDLINE_TEXT_LIMIT = 4000


@dataclass(frozen=True)
class Signature:
    name: str
    asset_type: AssetType
    expression: str


# Conservative patterns: match an executable / module / recognizable token,
# not general words such as 'agent' or 'python'.
# Claude Code is handled by its dedicated adapter in agent_clients/ and is
# intentionally absent from this table.
SIGNATURES = [
    Signature("Ollama", AssetType.LLM_SERVICE, r"(?<![\w-])ollama(?:\s+serve)?(?![\w-])"),
    Signature("vLLM", AssetType.LLM_SERVICE, r"(?:\bvllm\b|vllm\.entrypoints)"),
    Signature("LM Studio", AssetType.LLM_SERVICE, r"\blmstudio\b|\blm-studio\b"),
    Signature("Open WebUI", AssetType.AI_APPLICATION, r"\bopen-webui\b|\bopen_webui\b"),
    Signature("Dify", AssetType.AGENT_PLATFORM, r"(?:\bdify\b|\bdify-api\b)"),
    Signature("LangGraph", AssetType.AGENT_RUNTIME, r"\blanggraph\b"),
    Signature("LangChain", AssetType.AGENT_RUNTIME, r"\blangchain\b"),
    Signature("AutoGen", AssetType.AGENT_RUNTIME, r"\bautogen(?:_agentchat|_studio)?\b"),
    Signature("CrewAI", AssetType.AGENT_RUNTIME, r"\bcrewai\b"),
    Signature("AgentScope", AssetType.AGENT_RUNTIME, r"\bagentscope\b"),
    Signature("MCP Server", AssetType.MCP_SERVER, r"\bmcp[-_ ]server\b|\bmcp\.server\b|\bfastmcp\b"),
    Signature("Codex CLI", AssetType.AGENT_CLIENT, r"\bcodex(?:-cli)?\b"),
    Signature("OpenClaw", AssetType.AGENT_CLIENT, r"\bopenclaw\b"),
]
VERSION_RE = re.compile(r"(?<!\w)(?:--version[= ]|version[= ]|\bv)(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)", re.I)


class SignatureDetector:
    name = "signatures"

    def detect(self, facts: HostFacts) -> list[DetectedAsset]:
        ports_by_pid: dict[int, list[int]] = {}
        for sock in facts.sockets:
            if sock.pid is not None:
                ports_by_pid.setdefault(sock.pid, []).append(sock.port)
        assets: list[DetectedAsset] = []
        for proc in facts.processes:
            text = " ".join((proc.name, *proc.cmdline))
            for sig in SIGNATURES:
                if not re.search(sig.expression, text, re.I):
                    continue
                assets.append(self._asset(facts, sig, proc, text,
                                          ports_by_pid.get(proc.pid, [])))
        return assets

    def _asset(self, facts: HostFacts, sig: Signature, proc: ProcessInfo,
               text: str, ports: list[int]) -> DetectedAsset:
        claim = VERSION_RE.search(text)
        version = (VersionInfo(claim.group(1), VersionSource.PROCESS_CLAIM, 0.3)
                   if claim else VersionInfo.unknown())
        evidence = [Evidence(EvidenceKind.PROCESS,
                             f"process {proc.pid} matches {sig.name}",
                             {"pid": proc.pid, "name": proc.name,
                              "cmdline": redact(text)[:_CMDLINE_TEXT_LIMIT]}, 0.65)]
        evidence += [Evidence(EvidenceKind.LISTENING_SOCKET,
                              f"pid {proc.pid} listens on {port}",
                              {"pid": proc.pid, "port": port}, 0.85)
                     for port in ports]
        exe = proc.cmdline[0] if proc.cmdline else proc.name
        asset_id = build_asset_id(facts.hostname, slugify(sig.name),
                                  f"process:{normalize_path(exe)}")
        return DetectedAsset(
            asset_id=asset_id, name=sig.name, asset_type=sig.asset_type,
            states={AssetState.RUNNING},
            confidence=0.85 if ports else 0.65,
            version=version, evidence=evidence,
            running_pids=[proc.pid], listening_ports=ports, detector=self.name)
