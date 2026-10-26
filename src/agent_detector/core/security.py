"""Redaction helpers: raw credentials never reach evidence storage (plan section 3.1.2)."""
import re

_TOKEN_RE = re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{8,}")
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|secret|password|token)\b([=:\s]+)(\"?[^\s\"']+)")


def redact(text: str) -> str:
    text = _TOKEN_RE.sub("sk-***", text)
    text = _BEARER_RE.sub("Bearer ***", text)
    return _SECRET_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
