import os
from pathlib import Path

DB_PATH = Path(os.getenv("AGENT_DETECTOR_DB", "./data/agent_detector.sqlite3"))
MAX_PROBES = max(0, min(int(os.getenv("AGENT_DETECTOR_MAX_PROBES", "20")), 100))

GATEWAY_PORT = max(1, min(int(os.getenv("AGENT_DETECTOR_GATEWAY_PORT", "8899")), 65535))
GATEWAY_AGENT_LABEL = (os.getenv("AGENT_DETECTOR_GATEWAY_LABEL", "local-agent").strip()
                       or "local-agent")[:80]
GATEWAY_OBSERVED_HOSTS = os.getenv("AGENT_DETECTOR_GATEWAY_HOSTS", "127.0.0.1,localhost")
GATEWAY_PARSE_MAX_BYTES = min(max(int(os.getenv("AGENT_DETECTOR_GATEWAY_PARSE_MAX_BYTES",
                                                "65536")), 1024), 262144)
