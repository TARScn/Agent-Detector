"""Windows Sysmon collection (design section 4.1).

Two halves, deliberately separated:

* **parsing** — ``parse_event_xml`` turns one Sysmon event XML into a
  :class:`SysmonEvent`, and ``fact_from_event`` maps it onto the shared
  :class:`BehaviorFact`. Pure functions, testable on any platform.
* **subscription** — :class:`SysmonReader` uses the Windows Event Log API
  (``wevtapi.dll`` ``EvtSubscribe``) instead of polling ``Get-WinEvent`` or
  shelling out to PowerShell (design section 4.3). It delivers events to a
  callback and degrades to "unavailable" with a reason on non-Windows hosts,
  when Sysmon is not installed, or when the channel is not readable.

Scope note (design section 4.1): Sysmon file events do not cover every read,
write and rename. File **creation** and the configured **delete** events are
what this channel can honestly claim; anything else needs audit policy, ETW or
a filter driver.
"""
from __future__ import annotations

import ctypes
import logging
import re
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ElementTree
from collections import deque
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone

from agent_detector.core.facts import BehaviorFact

logger = logging.getLogger(__name__)

SUPPORTED_EVENTS = {
    1: "process.create",
    3: "network.connect",
    5: "process.terminate",
    11: "file.create",
    22: "dns.query",
    23: "file.delete",
    26: "file.delete.detected",
}

# Only the events that become behavior facts in this release.
FACT_EVENTS = {1, 3, 11, 23, 26}

DEFAULT_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DEFAULT_QUERY = ("*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=23 "
                 "or EventID=26)]]")

_EVENT_ID = re.compile(r"\d+$")
_TOKEN = re.compile(r'[^\s"]+|"([^"]*)"')


@dataclass(frozen=True)
class SysmonEvent:
    """The subset of a Sysmon event this product uses."""

    event_id: int
    name: str
    ts: float
    process_guid: str = ""
    parent_process_guid: str = ""
    pid: int | None = None
    ppid: int | None = None
    image: str = ""
    parent_image: str = ""
    command_line: str = ""
    user: str = ""
    target_filename: str = ""
    destination_ip: str = ""
    destination_hostname: str = ""
    destination_port: int | None = None
    query_name: str = ""
    raw: dict[str, str] = field(default_factory=dict)

    @property
    def process_name(self) -> str:
        return _basename(self.image)

    def to_dict(self) -> dict:
        return {"event_id": self.event_id, "name": self.name, "ts": self.ts,
                "process_guid": self.process_guid, "pid": self.pid,
                "ppid": self.ppid, "image": self.image,
                "command_line": self.command_line,
                "target": self.target_filename or self.destination_ip or self.query_name}


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def parse_event_xml(xml: str) -> SysmonEvent | None:
    """Parse one ``<Event>`` document; None when it is not a Sysmon event."""
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None
    if _local(root.tag) != "Event":
        return None
    system = _child(root, "System")
    if system is None:
        return None
    provider = _child(system, "Provider")
    if provider is not None and "Sysmon" not in (provider.get("Name") or ""):
        return None
    event_id = _event_id(system)
    if event_id is None or event_id not in SUPPORTED_EVENTS:
        return None
    fields = _event_data(root)
    return SysmonEvent(
        event_id=event_id, name=SUPPORTED_EVENTS[event_id],
        ts=_utc_time(fields.get("UtcTime") or _system_time(system)),
        process_guid=fields.get("ProcessGuid", ""),
        parent_process_guid=fields.get("ParentProcessGuid", ""),
        pid=_int(fields.get("ProcessId")), ppid=_int(fields.get("ParentProcessId")),
        image=fields.get("Image", ""), parent_image=fields.get("ParentImage", ""),
        command_line=fields.get("CommandLine", ""), user=fields.get("User", ""),
        target_filename=fields.get("TargetFilename", ""),
        destination_ip=fields.get("DestinationIp", ""),
        destination_hostname=fields.get("DestinationHostname", ""),
        destination_port=_int(fields.get("DestinationPort")),
        query_name=fields.get("QueryName", ""), raw=fields)


def _local(tag: str) -> str:
    """Tag name without its ``{namespace}`` prefix (Sysmon XML is namespaced)."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in element:
        if _local(child.tag) == name:
            return child
    return None


def _event_id(system: ElementTree.Element) -> int | None:
    node = _child(system, "EventID")
    if node is None or not node.text:
        return None
    match = _EVENT_ID.search(node.text.strip())
    return int(match.group(0)) if match else None


def _system_time(system: ElementTree.Element) -> str:
    node = _child(system, "TimeCreated")
    return (node.get("SystemTime") or "") if node is not None else ""


def _event_data(root: ElementTree.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    container = _child(root, "EventData")
    if container is None:
        return data
    for item in container:
        name = item.get("Name")
        if name:
            data[name] = (item.text or "").strip()
    return data


def _utc_time(value: str) -> float:
    """Sysmon prints ``2026-10-20 09:40:00.123`` (UTC) or ISO-8601."""
    if not value:
        return 0.0
    text = value.strip().replace("Z", "+00:00")
    for parse in (lambda s: datetime.fromisoformat(s),
                  lambda s: datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f"),
                  lambda s: datetime.strptime(s, "%Y-%m-%d %H:%M:%S")):
        try:
            parsed = parse(text)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    return 0.0


def _int(value: str | None) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1] if path else ""


def split_command_line(command_line: str) -> tuple[str, ...]:
    """Split a Windows command line into argv-ish tokens (quotes honoured)."""
    if not command_line:
        return ()
    tokens: list[str] = []
    for match in _TOKEN.finditer(command_line):
        quoted = match.group(1)
        if quoted is not None:
            tokens.append(quoted)
        else:
            tokens.append(match.group(0))
    return tuple(tokens)


def fact_from_event(event: SysmonEvent) -> BehaviorFact | None:
    """Map a Sysmon event onto the shared fact layer (design section 4.2)."""
    if event.event_id not in FACT_EVENTS or event.pid is None:
        return None
    evidence = ("sysmon", f"sysmon_event:{event.event_id}")
    if event.process_guid:
        evidence += (f"process_guid:{event.process_guid}",)
    serial = event.process_guid or f"{event.pid}-{int(event.ts)}"
    common = {"ts": event.ts, "serial": serial, "pid": event.pid,
              "ppid": event.ppid, "process_name": event.process_name,
              "exe": event.image or None}
    if event.event_id == 1:
        return BehaviorFact(kind="proc.exec", evidence=evidence,
                            argv=split_command_line(event.command_line), **common)
    if event.event_id == 11:
        return BehaviorFact(kind="file.write", evidence=evidence,
                            path=event.target_filename or None, **common)
    if event.event_id in (23, 26):
        return BehaviorFact(kind="file.delete", evidence=evidence,
                            path=event.target_filename or None, **common)
    if event.event_id == 3:
        endpoint = (f"{event.destination_ip}:{event.destination_port}"
                    if event.destination_ip and event.destination_port else
                    event.destination_ip or event.destination_hostname)
        net_evidence = evidence
        if event.destination_hostname:
            net_evidence = evidence + (f"host:{event.destination_hostname}",)
        return BehaviorFact(kind="net.connect", endpoint=endpoint or None,
                            argv=split_command_line(event.command_line),
                            evidence=net_evidence, **common)
    return None


# ---------------------------------------------------------------------------
# availability
# ---------------------------------------------------------------------------


@dataclass
class SysmonAvailability:
    available: bool
    reason: str = ""
    channel: str = DEFAULT_CHANNEL
    service: str = ""

    def to_dict(self) -> dict:
        return {"available": self.available, "reason": self.reason,
                "channel": self.channel, "service": self.service}


def sysmon_available(channel: str = DEFAULT_CHANNEL) -> SysmonAvailability:
    """Can this host deliver Sysmon events right now?

    Checks the channel configuration (``EvtOpenChannelConfig``) rather than a
    query handle: ``EvtQuery`` happily returns a handle for a channel that does
    not exist when query errors are tolerated, which would report a collector
    as healthy on a host with no Sysmon at all.
    """
    if sys.platform != "win32":
        return SysmonAvailability(False, "非 Windows 主机：Sysmon 通道不可用（请使用 "
                                         "auditd 或采样模式）", channel)
    service = sysmon_service_name()
    api = _wevtapi()
    if api is None:
        return SysmonAvailability(False, "无法加载 wevtapi.dll", channel, service)
    exists, enabled, reason = _channel_state(api, channel)
    if not exists:
        return SysmonAvailability(False, f"{reason}（通道 {channel}）", channel, service)
    if not enabled:
        return SysmonAvailability(False, f"{reason}（通道 {channel}）", channel, service)
    return SysmonAvailability(True, "Sysmon 事件通道可读", channel, service)


def _channel_state(api, channel: str) -> tuple[bool, bool, str]:
    """(exists, enabled, reason) for one event channel."""
    import ctypes.wintypes as wintypes

    handle = api.EvtOpenChannelConfig(None, channel, 0)
    if not handle:
        return False, False, "未安装 Sysmon：事件通道不存在"
    try:
        used = wintypes.DWORD(0)
        api.EvtGetChannelConfigProperty(handle, _EVT_CHANNEL_CONFIG_ENABLED, 0, 0,
                                        None, ctypes.byref(used))
        size = max(used.value, 4)
        buffer = ctypes.create_string_buffer(size)
        if not api.EvtGetChannelConfigProperty(handle, _EVT_CHANNEL_CONFIG_ENABLED, 0,
                                               size, buffer, ctypes.byref(used)):
            return True, True, ""  # exists, flag unreadable: assume enabled
        enabled = bool(ctypes.c_uint32.from_buffer(buffer).value)
        return True, enabled, "" if enabled else "事件通道存在但未启用"
    finally:
        api.EvtClose(handle)


def sysmon_service_name() -> str:
    """'Sysmon64' / 'Sysmon' when the service exists, else ''."""
    if sys.platform != "win32":
        return ""
    for name in ("Sysmon64", "Sysmon"):
        for candidate in (shutil.which(f"{name}.exe"),
                          rf"C:\Windows\{name}.exe"):
            if candidate and candidate.lower().endswith(".exe"):
                if Path(candidate).exists():
                    return name
    try:
        proc = subprocess.run(["sc", "query", "Sysmon64"], capture_output=True,
                              timeout=5, errors="replace")
        if proc.returncode == 0:
            return "Sysmon64"
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def config_snippet(channel: str = DEFAULT_CHANNEL) -> str:
    """The Sysmon config lines the operator should merge (see configs/sysmon.xml)."""
    return (f"# channel: {channel}\n"
            "# ProcessCreate=1, NetworkConnect=3, ProcessTerminate=5, FileCreate=11,\n"
            "# DnsQuery=22, FileDelete=23/26\n"
            "# NetworkConnect is off by default and must be enabled explicitly.\n")


# ---------------------------------------------------------------------------
# subscription (Windows Event Log API via ctypes)
# ---------------------------------------------------------------------------

_EVT_RENDER_EVENT_XML = 1
_EVT_CHANNEL_CONFIG_ENABLED = 0
_SUBSCRIBE_TO_FUTURE = 1
_SUBSCRIBE_START_OLDEST = 2
_ERROR_INSUFFICIENT_BUFFER = 122
_wevtapi_lock = threading.Lock()
_wevtapi_dll = None


def _wevtapi():
    global _wevtapi_dll
    if sys.platform != "win32":
        return None
    with _wevtapi_lock:
        if _wevtapi_dll is None:
            try:
                dll = ctypes.WinDLL("wevtapi.dll")  # type: ignore[attr-defined]
            except OSError:
                return None
            _bind_wevtapi(dll)
            _wevtapi_dll = dll
        return _wevtapi_dll


def _bind_wevtapi(dll) -> None:
    import ctypes.wintypes as wintypes

    dll.EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                             wintypes.DWORD]
    dll.EvtQuery.restype = wintypes.HANDLE
    dll.EvtClose.argtypes = [wintypes.HANDLE]
    dll.EvtClose.restype = wintypes.BOOL
    dll.EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD,
                              wintypes.DWORD, ctypes.c_void_p,
                              ctypes.POINTER(wintypes.DWORD),
                              ctypes.POINTER(wintypes.DWORD)]
    dll.EvtRender.restype = wintypes.BOOL
    dll.EvtSubscribe.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR,
                                 wintypes.LPCWSTR, wintypes.HANDLE, ctypes.c_void_p,
                                 _CALLBACK_TYPE, wintypes.DWORD]
    dll.EvtSubscribe.restype = wintypes.HANDLE
    dll.EvtOpenChannelConfig.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                                         wintypes.DWORD]
    dll.EvtOpenChannelConfig.restype = wintypes.HANDLE
    dll.EvtGetChannelConfigProperty.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                wintypes.DWORD, wintypes.DWORD,
                                                ctypes.c_void_p,
                                                ctypes.POINTER(wintypes.DWORD)]
    dll.EvtGetChannelConfigProperty.restype = wintypes.BOOL


_CALLBACK_TYPE = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                                    ctypes.c_void_p) if sys.platform == "win32" else ctypes.CFUNCTYPE(
    ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p)


class SysmonReader:
    """Live Sysmon subscription: events land in an internal bounded deque."""

    def __init__(self, channel: str = DEFAULT_CHANNEL, *, query: str | None = None,
                 start_from_oldest: bool = False, buffer_size: int = 2000):
        self.channel = channel
        self.query = query or DEFAULT_QUERY
        self.start_from_oldest = start_from_oldest
        self._events: deque[SysmonEvent] = deque(maxlen=buffer_size)
        self._raw: deque[str] = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        self._api = None
        self._subscription = None
        self._callback = None
        self.unparsed = 0
        self.received = 0

    @property
    def running(self) -> bool:
        return self._subscription is not None

    def start(self) -> None:
        """Subscribe; raises RuntimeError with the availability reason."""
        availability = sysmon_available(self.channel)
        if not availability.available:
            raise RuntimeError(availability.reason)
        api = _wevtapi()
        assert api is not None
        self._api = api
        flags = (_SUBSCRIBE_START_OLDEST if self.start_from_oldest
                 else _SUBSCRIBE_TO_FUTURE)
        self._callback = _CALLBACK_TYPE(self._on_event)
        handle = api.EvtSubscribe(None, None, self.channel, self.query, None, None,
                                  self._callback, flags)
        if not handle:
            raise RuntimeError(f"EvtSubscribe 失败（通道 {self.channel}）")
        self._subscription = handle

    def _on_event(self, action: int, _context, event_handle) -> int:
        try:
            if action == 0 and event_handle:  # EvtSubscribeActionDeliver
                xml = self._render(event_handle)
                if xml:
                    self.received += 1
                    parsed = parse_event_xml(xml)
                    with self._lock:
                        if parsed is not None:
                            self._events.append(parsed)
                        else:
                            self.unparsed += 1
                            self._raw.append(xml)
        except Exception:  # a bad event must not kill the subscription
            logger.exception("sysmon callback failed")
        return 0

    def _render(self, event_handle) -> str | None:
        import ctypes.wintypes as wintypes

        api = self._api
        used = wintypes.DWORD(0)
        props = wintypes.DWORD(0)
        if api.EvtRender(None, event_handle, _EVT_RENDER_EVENT_XML, 0, None,
                         ctypes.byref(used), ctypes.byref(props)):
            return None
        if used.value == 0:
            return None
        buffer = ctypes.create_unicode_buffer(used.value // ctypes.sizeof(ctypes.c_wchar) + 1)
        if not api.EvtRender(None, event_handle, _EVT_RENDER_EVENT_XML, used.value,
                             buffer, ctypes.byref(used), ctypes.byref(props)):
            return None
        return buffer.value

    def poll(self) -> list[SysmonEvent]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
        return events

    def poll_raw(self) -> list[str]:
        with self._lock:
            raw = list(self._raw)
            self._raw.clear()
        return raw

    def close(self) -> None:
        api, handle = self._api, self._subscription
        self._subscription = None
        if api is not None and handle:
            try:
                api.EvtClose(handle)
            except Exception:  # closing twice must not raise
                logger.debug("sysmon subscription close failed", exc_info=True)
        self._callback = None

    def status(self) -> dict:
        return {"running": self.running, "channel": self.channel,
                "received": self.received, "unparsed": self.unparsed,
                "pending": len(self._events)}


def tail_once(channel: str = DEFAULT_CHANNEL, *, seconds: float = 2.0,
              query: str | None = None) -> list[SysmonEvent]:
    """Subscribe for a short window and return what arrived (used by the CLI)."""
    reader = SysmonReader(channel, query=query)
    reader.start()
    deadline = time.monotonic() + max(seconds, 0.1)
    try:
        while time.monotonic() < deadline:
            time.sleep(0.1)
        return reader.poll()
    finally:
        reader.close()