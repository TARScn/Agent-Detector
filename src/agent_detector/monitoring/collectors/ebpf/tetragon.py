"""Tetragon channel availability probe and install command printing.

Mirrors the other channels' honest probes (``sysmon_available``, auditd's
platform check): the tool reports what it can see and prints commands for a
human to run — it never elevates privileges or touches the kernel itself.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from agent_detector.core.config import TETRA_LOG

# Pinned so the documented event shapes (parser.py) stay true; bump deliberately.
TETRAGON_VERSION = "v1.7.1"


@dataclass(frozen=True)
class TetragonAvailability:
    available: bool
    reason: str
    log_path: str

    def to_dict(self) -> dict:
        return {"available": self.available, "reason": self.reason,
                "log_path": self.log_path}


def tetragon_available(log_path=None) -> TetragonAvailability:
    """The channel is usable when the JSON export exists and is readable.

    The collector tails the file, so readability is exactly the capability it
    needs — no gRPC, no kernel handle, no daemon query.
    """
    path = Path(log_path) if log_path else Path(TETRA_LOG)
    if sys.platform != "linux":
        return TetragonAvailability(False, "非 Linux 主机：eBPF 通道不可用", str(path))
    if not path.exists():
        return TetragonAvailability(
            False, "导出文件不存在：Tetragon 未安装或未配置 --export-filename", str(path))
    try:
        with path.open("r", encoding="utf-8", errors="replace"):
            return TetragonAvailability(True, "", str(path))
    except OSError as exc:
        return TetragonAvailability(
            False, f"导出文件不可读：{exc}（export-file-perm 默认 600，需 root 或调整权限）",
            str(path))


def install_commands(log_path=None) -> list[str]:
    """Standalone (systemd) deployment steps for the pinned Tetragon release."""
    target = log_path or TETRA_LOG
    version = TETRAGON_VERSION
    return [
        f"curl -fSL -o /tmp/tetragon.tar.gz https://github.com/cilium/tetragon/"
        f"releases/download/{version}/tetragon-{version}-amd64.tar.gz",
        "sudo tar -xzf /tmp/tetragon.tar.gz -C /tmp",
        f"sudo bash /tmp/tetragon-{version}-amd64/install.sh",
        "sudo mkdir -p /var/log/tetragon",
        f"sudo printf '{target}\\n' > /etc/tetragon/tetragon.conf.d/export-filename",
        "sudo printf 'true\\n' > /etc/tetragon/tetragon.conf.d/enable-process-ns",
        "sudo systemctl restart tetragon",
        "systemctl is-active tetragon && sudo tail -1 " + str(target),
    ]


def uninstall_commands() -> list[str]:
    return [
        "sudo systemctl disable --now tetragon",
        "sudo bash /tmp/tetragon-"
        + TETRAGON_VERSION + "-amd64/uninstall.sh  # 或直接删除 /usr/local/bin/tetragon",
    ]
