"""LLM base-model probe: read the Agent's own config files for model + provider.

Driven by the ``llm:`` section of each client rule (fingerprints/rules/*.yaml):
one source per config file, ``fields`` mapping reserved names (``model`` /
``base_url`` / ``provider_id``) to dotted paths into the parsed document. A
path may reference an earlier field via ``{name}`` (Codex picks its provider
table by the ``model_provider`` value) and use ``*`` to expand across all keys
at a level (OpenCode keeps a dict of providers).

Privacy (same stance as mcp.py): only model strings and http(s) endpoints are
captured — never file contents, never anything key-shaped. The provider name
is resolved from the endpoint host via discovery/data/llm_providers.yaml; a
loopback endpoint is reported as a local relay whose upstream is unknown.
"""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

# Anything key-shaped is never captured, whatever the rule says.
_SECRET_RE = re.compile(r"sk-[A-Za-z0-9_-]{8,}|[A-Za-z0-9_-]{32,}\.[A-Za-z0-9_-]{8,}")


@dataclass(frozen=True)
class LlmEndpoint:
    """One model/provider pairing read from an Agent's config."""

    model: str
    base_url: str
    provider: str
    provider_id: str
    source: str

    def to_dict(self) -> dict:
        return {"model": self.model, "base_url": self.base_url,
                "provider": self.provider, "provider_id": self.provider_id,
                "source": self.source}


def load_provider_map(data_file: Path | None = None) -> list[tuple[str, str]]:
    """(host, vendor) pairs from discovery/data/llm_providers.yaml; broken file -> []."""
    target = data_file or Path(__file__).resolve().parent.parent / "data" / "llm_providers.yaml"
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        return [(str(p["host"]).lower(), str(p["vendor"]))
                for p in raw.get("providers", []) if p.get("host") and p.get("vendor")]
    except (OSError, yaml.YAMLError, KeyError, TypeError):
        return []


def resolve_provider(base_url: str, provider_map: list[tuple[str, str]]) -> str:
    """Translate an endpoint URL into a vendor name via host-suffix match."""
    try:
        host = (urlsplit(base_url).hostname or "").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    if host == "127.0.0.1" or host == "::1" or host.endswith(".localhost") \
            or host == "localhost":
        return "本地中转（上游未知）"
    for mapped_host, vendor in provider_map:
        if host == mapped_host or host.endswith("." + mapped_host):
            return vendor
    return ""


def _load_document(path: Path, fmt: str) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    try:
        if fmt == "toml":
            return tomllib.loads(text)
        if fmt == "jsonc":  # strip whole-line // comments before parsing
            text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
        data = json.loads(text)
    except (ValueError, UnicodeError):
        return None
    return data if isinstance(data, dict) else None


def _safe_str(value) -> str:
    """Keep only short scalar strings; key-shaped values are dropped entirely."""
    if not isinstance(value, str):
        if isinstance(value, (int, float, bool)):
            value = str(value)
        else:
            return ""
    value = value.strip()
    if not value or len(value) > 300 or _SECRET_RE.search(value):
        return ""
    return value


def _resolve_fields(doc: dict, fields: dict[str, str]) -> dict[tuple, dict[str, str]]:
    """Resolve every field path; returns {expansion-group: {field: value}}.

    ``*`` in a path expands across that level's keys; the instantiated keys
    form the group key so fields expanded through the same branches merge
    into one endpoint.
    """
    captured: dict[tuple, dict[str, str]] = {}

    def walk(node, segments, group):
        if node is None:
            return
        if not segments:
            value = _safe_str(node)
            if value:
                captured.setdefault(group, {})[field_name] = value
            return
        if not isinstance(node, dict):
            return
        head, rest = segments[0], segments[1:]
        if head == "*":
            for key in node:
                walk(node[key], rest, group + (key,))
        else:
            walk(node.get(head), rest, group)

    resolved_refs: dict[str, str] = {}
    for field_name, path in fields.items():
        substituted = re.sub(
            r"\{(\w+)\}",
            lambda m: resolved_refs.get(m.group(1), ""),
            path)
        # A {ref} that resolved to nothing voids the whole path (Codex without
        # model_provider has no provider table to look into).
        if re.search(r"\{\w+\}", substituted):
            continue
        walk(doc, substituted.split("."), ())
        if field_name in captured.get((), {}):
            resolved_refs[field_name] = captured[()][field_name]
    return captured


def endpoints_for(rule, home: Path | None = None,
                  provider_map: list[tuple[str, str]] | None = None) -> list[LlmEndpoint]:
    """Read every source the rule's ``llm`` section declares; missing files -> [].

    ``rule`` is a ClientRule; taking the object (not an agent_type string)
    keeps the config paths declarative in the rule file, never in code.
    """
    spec = getattr(rule, "llm", None)
    if spec is None or not spec.sources:
        return []
    base = Path(home) if home else Path.home()
    provider_map = provider_map if provider_map is not None else load_provider_map()
    endpoints: list[LlmEndpoint] = []
    for source in spec.sources:
        path = base / source.path[1:].lstrip("/\\") if source.path.startswith("~") \
            else Path(source.path)
        doc = _load_document(path, source.format)
        if doc is None:
            continue
        groups = _resolve_fields(doc, source.fields)
        expanded = {group: captured for group, captured in groups.items() if group}
        if expanded and () in groups:
            # 源级字段（如顶层 model）没有经过 * 展开：把它们作为默认值合并进
            # 每个展开组，而不是单独产出一条"只有模型没有端点"的记录。
            bare = groups[()]
            for captured in expanded.values():
                for name, value in bare.items():
                    captured.setdefault(name, value)
            groups = expanded
        for group, captured in groups.items():
            model = captured.get("model", "")
            base_url = captured.get("base_url", "")
            if not model and not base_url:
                continue
            provider_id = captured.get("provider_id", "")
            provider = (resolve_provider(base_url, provider_map) if base_url
                        else source.default_provider)
            endpoints.append(LlmEndpoint(
                model=model, base_url=base_url, provider=provider,
                provider_id=provider_id, source=str(path)))
    return endpoints
