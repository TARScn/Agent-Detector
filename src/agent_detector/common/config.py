import os
from pathlib import Path


def _env_flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _env_choice(name: str, choices: tuple[str, ...], default: str) -> str:
    value = os.getenv(name, default).strip().lower()
    return value if value in choices else default


DB_PATH = Path(os.getenv("AGENT_DETECTOR_DB", "./data/agent_detector.sqlite3"))
MAX_PROBES = max(0, min(int(os.getenv("AGENT_DETECTOR_MAX_PROBES", "20")), 100))

MONITOR_INTERVAL = min(max(float(os.getenv("AGENT_DETECTOR_MONITOR_INTERVAL", "2.0")),
                           0.5), 60.0)
MONITOR_SUPPRESS_SECONDS = min(max(int(os.getenv("AGENT_DETECTOR_MONITOR_SUPPRESS", "300")),
                                   0), 86400)

# System behavior channel (behavior/audit + poll). See docs/syscall-monitoring.md.
BEHAVIOR_AUDIT_LOG = os.getenv("AGENT_DETECTOR_AUDIT_LOG", "/var/log/audit/audit.log")
BEHAVIOR_AUDIT_KEYS = tuple(key.strip() for key in os.getenv(
    "AGENT_DETECTOR_AUDIT_KEYS",
    "agent_detector_exec,agent_detector_file,agent_detector_read,"
    "agent_detector_net,agent_detector_kill").split(",") if key.strip())
BEHAVIOR_SUPPRESS_SECONDS = min(max(int(os.getenv("AGENT_DETECTOR_BEHAVIOR_SUPPRESS",
                                                  "300")), 0), 86400)
BEHAVIOR_INCLUDE_UNATTRIBUTED = _env_flag("AGENT_DETECTOR_BEHAVIOR_INCLUDE_UNATTRIBUTED")
BEHAVIOR_RETENTION_DAYS = min(max(int(os.getenv("AGENT_DETECTOR_BEHAVIOR_RETENTION_DAYS",
                                                "30")), 0), 3650)
BEHAVIOR_MAX_EVENTS_PER_MINUTE = min(max(int(os.getenv(
    "AGENT_DETECTOR_BEHAVIOR_MAX_EVENTS_PER_MINUTE", "600")), 0), 100000)
BEHAVIOR_PATH_POLICY = _env_choice("AGENT_DETECTOR_BEHAVIOR_PATH_POLICY",
                                   ("full", "basename"), "full")
BEHAVIOR_STORE_ARGV = _env_flag("AGENT_DETECTOR_BEHAVIOR_STORE_ARGV")
BEHAVIOR_POLL_INTERVAL = min(max(float(os.getenv("AGENT_DETECTOR_BEHAVIOR_POLL_INTERVAL",
                                                 "2.0")), 0.5), 60.0)
