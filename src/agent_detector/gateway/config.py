"""Environment-based configuration shared by the proxy addon and the manager.

The manager (web/CLI process) spawns mitmdump with these AGD_* variables set,
so the addon process picks up its configuration from its environment without
importing the main application config.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    db_path: Path
    agent_id: str
    observed_hosts: frozenset[str]
    parse_max_bytes: int

    @classmethod
    def load(cls) -> "Settings":
        hosts = os.environ.get("AGD_OBSERVED_HOSTS", "127.0.0.1,localhost")
        max_size = min(max(int(os.environ.get("AGD_PARSE_MAX_BYTES", "65536")), 1024), 262144)
        # The label is an operator declaration, not proof of the originating process.
        agent_id = os.environ.get("AGD_AGENT_ID", "local-agent").strip() or "unattributed"
        return cls(
            db_path=Path(os.environ.get("AGD_DB_PATH", "./data/agent_detector.sqlite3")).expanduser(),
            agent_id=agent_id[:80],
            observed_hosts=frozenset(h.strip().lower() for h in hosts.split(",") if h.strip()),
            parse_max_bytes=max_size,
        )

    def is_observed(self, host: str) -> bool:
        # Exact host match only; no suffix tricks (e.g. api.openai.com.evil.tld).
        return host.lower().rstrip(".") in self.observed_hosts
