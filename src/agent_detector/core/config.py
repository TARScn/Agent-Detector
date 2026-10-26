import os
import secrets
from pathlib import Path


def _env_flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _env_choice(name: str, choices: tuple[str, ...], default: str) -> str:
    value = os.getenv(name, default).strip().lower()
    return value if value in choices else default


DB_PATH = Path(os.getenv("AGENT_DETECTOR_DB", "./data/agent_detector.sqlite3"))
MAX_PROBES = max(0, min(int(os.getenv("AGENT_DETECTOR_MAX_PROBES", "20")), 100))
# Self-built agent discovery budget: python/node processes resolved to projects
# per scan (AGENT_DETECTOR_MAX_PROJECTS). Guards the project resolver against
# pathological process tables, like MAX_PROBES does for the HTTP prober.
MAX_PROJECT_PROBES = max(0, min(int(os.getenv("AGENT_DETECTOR_MAX_PROJECTS", "40")), 500))

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

# ---------------------------------------------------------------------------
# V0.2: control plane, hook bridge and policy (design sections 5, 6, 8)
# ---------------------------------------------------------------------------

# Where the console and the hook decision endpoint listen. The service binds
# to loopback by default: the decision endpoint is an internal API and must
# not be reachable from the network without an explicit decision.
WEB_HOST = os.getenv("AGENT_DETECTOR_HOST", "127.0.0.1")
WEB_PORT = max(1, min(int(os.getenv("AGENT_DETECTOR_PORT", "8787")), 65535))

# Hook bridge transport. The token file is created on first use with owner-only
# permissions; a Named Pipe with a user SID ACL is the planned desktop
# replacement (design section 8), not implemented yet.
HOOK_URL = os.getenv("AGENT_DETECTOR_HOOK_URL",
                     f"http://127.0.0.1:{WEB_PORT}/internal/v1/hooks/decide")
HOOK_TOKEN_PATH = Path(os.getenv("AGENT_DETECTOR_HOOK_TOKEN_FILE",
                                 str(DB_PATH.parent / "hook.token")))
HOOK_TIMEOUT_SECONDS = min(max(float(os.getenv("AGENT_DETECTOR_HOOK_TIMEOUT", "5")), 0.5), 30.0)
# What the bridge does when the decision service cannot answer. "block" is the
# fail-closed default; "allow" is the audit-mode behaviour and is logged.
HOOK_FAILURE_MODE = _env_choice("AGENT_DETECTOR_HOOK_FAILURE_MODE",
                                ("block", "allow"), "block")

# Policy rules (packaged default + optional override directory) and the
# capability matrix that tells the UI what each Agent is supposed to support.
POLICY_DIR = os.getenv("AGENT_DETECTOR_POLICY_DIR", "")
AGENTS_FILE = os.getenv("AGENT_DETECTOR_AGENTS_FILE", "")
# Telemetry events at or above this risk raise a security alert.
ALERT_RISK_LEVEL = _env_choice("AGENT_DETECTOR_ALERT_RISK_LEVEL",
                               ("medium", "high", "critical"), "high")

# Windows Sysmon channel and connection event capture (design section 4.1).
SYSMON_CHANNEL = os.getenv("AGENT_DETECTOR_SYSMON_CHANNEL",
                           "Microsoft-Windows-Sysmon/Operational")
SYSMON_BOOKMARK = Path(os.getenv("AGENT_DETECTOR_SYSMON_BOOKMARK",
                                 str(DB_PATH.parent / "sysmon.bookmark.xml")))


def hook_token(*, create: bool = True) -> str:
    """Return the internal-API token, generating one on first use.

    The token only guards the loopback decision endpoint against other local
    processes; it is not a substitute for OS-level access control.
    """
    token = os.getenv("AGENT_DETECTOR_HOOK_TOKEN", "").strip()
    if token:
        return token
    try:
        token = HOOK_TOKEN_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    if token or not create:
        return token
    token = secrets.token_urlsafe(32)
    HOOK_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    HOOK_TOKEN_PATH.write_text(token, encoding="utf-8")
    try:
        os.chmod(HOOK_TOKEN_PATH, 0o600)
    except OSError:  # best effort: Windows ACLs ignore POSIX mode bits
        pass
    return token
