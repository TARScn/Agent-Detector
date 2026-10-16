import os
from pathlib import Path

DB_PATH = Path(os.getenv("AGENT_DETECTOR_DB", "./data/agent_detector.sqlite3"))
MAX_PROBES = max(0, min(int(os.getenv("AGENT_DETECTOR_MAX_PROBES", "20")), 100))
