"""Stable asset identity, independent of recyclable PIDs (plan section 5.3)."""
import hashlib
import re
from pathlib import Path


def slugify(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return cleaned or "unknown"


def normalize_path(path) -> str:
    """Canonical form for identity purposes: resolved, forward slashes, lowercase drive."""
    try:
        resolved = Path(path).expanduser().resolve()
    except OSError:
        resolved = Path(path).expanduser()
    text = str(resolved).replace("\\", "/")
    if len(text) >= 2 and text[1] == ":":
        text = text[0].lower() + text[2:]
    return text.rstrip("/") or "/"


def build_asset_id(hostname: str, agent_key: str, scope: str) -> str:
    digest = hashlib.sha256(
        f"{hostname.strip().lower()}|{agent_key}|{scope}".encode("utf-8")).hexdigest()[:12]
    return f"{agent_key}--{digest}"
