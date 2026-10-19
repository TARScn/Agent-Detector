import os
from pathlib import Path

DB_PATH = Path(os.getenv("AGENT_DETECTOR_DB", "./data/agent_detector.sqlite3"))
MAX_PROBES = max(0, min(int(os.getenv("AGENT_DETECTOR_MAX_PROBES", "20")), 100))

MONITOR_INTERVAL = min(max(float(os.getenv("AGENT_DETECTOR_MONITOR_INTERVAL", "2.0")),
                           0.5), 60.0)
MONITOR_SUPPRESS_SECONDS = min(max(int(os.getenv("AGENT_DETECTOR_MONITOR_SUPPRESS", "300")),
                                   0), 86400)
