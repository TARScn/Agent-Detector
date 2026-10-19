"""Windows DNS cache correlation without admin rights (plan §3.1.4).

The system resolver cache maps recent answers (ip -> hostname) and any user
can read it via Get-DnsClientCache. Correlating outbound destinations against
this cache turns 'pid -> 104.18.x.x:443' into 'pid -> api.anthropic.com'.
Boundaries, accepted for connection-level evidence: cached answers expire
with their TTL, and DNS-over-HTTPS bypasses this cache entirely.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time

_REFRESH_SECONDS = 15.0
_PS_SCRIPT = ("Get-DnsClientCache -ErrorAction SilentlyContinue | "
              "Select-Object Entry,Data | ConvertTo-Json -Compress")


def parse_dns_cache_json(raw: str | None) -> dict[str, str]:
    """Parse PowerShell JSON output into {ip: hostname}; last entry wins."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if isinstance(data, dict):
        data = [data]
    mapping: dict[str, str] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        host = str(item.get("Entry") or "").strip().rstrip(".").lower()
        ip = str(item.get("Data") or "").strip()
        if host and ip:
            mapping[ip] = host
    return mapping


class DnsCache:
    """Throttled snapshot reader; never raises, degrades to an empty map."""

    def __init__(self, refresh_seconds: float = _REFRESH_SECONDS):
        self.refresh_seconds = refresh_seconds
        self._mapping: dict[str, str] = {}
        self._last_refresh = 0.0
        self.failed = False

    def snapshot(self) -> dict[str, str]:
        now = time.monotonic()
        if now - self._last_refresh < self.refresh_seconds:
            return self._mapping
        self._last_refresh = now
        if sys.platform != "win32":
            self._mapping = {}
            return self._mapping
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", _PS_SCRIPT],
                capture_output=True, text=True, timeout=10, check=False)
            self._mapping = parse_dns_cache_json(completed.stdout)
            self.failed = completed.returncode != 0 and not self._mapping
        except (OSError, subprocess.SubprocessError):
            self.failed = True
            self._mapping = {}
        return self._mapping
