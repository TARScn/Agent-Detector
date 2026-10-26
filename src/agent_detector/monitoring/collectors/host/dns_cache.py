"""Windows DNS cache correlation without admin rights (plan §3.1.4).

The system resolver cache maps recent answers (ip -> hostname) and any user
can read it via Get-DnsClientCache. A **persistent** PowerShell reader (the
cmdlet costs ~350ms per call — too heavy to spawn per poll) refreshes every
second, and results are merged into a retention window: CDN answers can carry
TTL as low as 2 seconds, so matching only against the live cache would miss
most lookups. `ip -> host` mappings therefore stay usable for a retention
period after they leave the OS cache.

Boundaries, accepted for connection-level evidence: DNS-over-HTTPS bypasses
this cache entirely, and retained mappings decay — an IP that changed owners
inside the retention window can still carry its previous name.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time

_READ_INTERVAL_MS = 1000
_RETENTION_SECONDS = 900.0
_PS_LOOP = (
    "$ErrorActionPreference = 'SilentlyContinue'\n"
    "while ($true) {\n"
    "  $c = Get-DnsClientCache | Select-Object Entry,Data\n"
    "  [Console]::Out.WriteLine((ConvertTo-Json -InputObject @($c) -Compress))\n"
    "  [Console]::Out.Flush()\n"
    "  Start-Sleep -Milliseconds __INTERVAL_MS__\n"
    "}\n"
)


def parse_dns_cache_json(raw: str | None) -> dict[str, str]:
    """Parse one PowerShell JSON dump into {ip: hostname}; last entry wins."""
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
    """Persistent reader with merge retention; degrades to an empty map.

    Entries carry their provenance: "cache" (observed in the OS resolver
    cache, i.e. someone actually resolved it) or "probe" (the monitor
    proactively resolved a known-LLM host — needed because Chromium-based
    apps use a built-in resolver that never touches the Windows DNS cache).
    """

    def __init__(self, read_interval_ms: int = _READ_INTERVAL_MS,
                 retention_seconds: float = _RETENTION_SECONDS):
        self.read_interval_ms = read_interval_ms
        self.retention_seconds = retention_seconds
        # ip -> {host: (last_seen_monotonic, origin)}; several names per IP
        # are kept because CDN addresses are shared.
        self._entries: dict[str, dict[str, tuple[float, str]]] = {}
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self.failed = False

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def entry_count(self) -> int:
        with self._lock:
            return sum(len(hosts) for hosts in self._entries.values())

    def merge_proactive(self, mapping: dict[str, str]) -> None:
        """Public merge for monitor-initiated resolution of known LLM hosts."""
        self._merge(mapping, origin="probe")

    def start(self) -> None:
        if self.running:
            return
        if sys.platform != "win32":
            self.failed = True
            return
        script = _PS_LOOP.replace("__INTERVAL_MS__", str(self.read_interval_ms))
        try:
            self._proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-Command", script],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace")
        except OSError:
            self.failed = True
            return
        self._thread = threading.Thread(target=self._read_loop, daemon=True,
                                        name="agent-detector-dnscache")
        self._thread.start()

    def close(self) -> None:
        proc, thread = self._proc, self._thread
        self._proc, self._thread = None, None
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                try:
                    proc.kill()
                except OSError:
                    pass
        if thread is not None:
            thread.join(timeout=5)

    def snapshot(self) -> dict[str, tuple[tuple[str, str], ...]]:
        """{ip: ((host, origin), ...)} from retained mappings; no side effects."""
        cutoff = time.monotonic() - self.retention_seconds
        with self._lock:
            result: dict[str, tuple[tuple[str, str], ...]] = {}
            for ip in list(self._entries):
                alive = tuple((host, origin) for host, (ts, origin)
                              in self._entries[ip].items() if ts >= cutoff)
                if alive:
                    result[ip] = alive
                else:
                    del self._entries[ip]
            return result

    # -- internal ----------------------------------------------------------

    def _read_loop(self) -> None:
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        for line in proc.stdout:
            fresh = parse_dns_cache_json(line)
            if fresh:
                self._merge(fresh, origin="cache")
        self.failed = True  # reader ended (process died)

    def _ingest(self, line: str) -> None:
        fresh = parse_dns_cache_json(line)
        if fresh:
            self._merge(fresh, origin="cache")

    def _merge(self, mapping: dict[str, str], origin: str) -> None:
        now = time.monotonic()
        with self._lock:
            for ip, host in mapping.items():
                self._entries.setdefault(ip, {})[host] = (now, origin)