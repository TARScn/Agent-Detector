"""Raw auditd log parsing: group records into events keyed by the audit serial.

The parser is deliberately dependency-free and testable from fixture files; the
same code path serves live tailing and offline replay.

Value conventions in auditd logs:
- quoted values are literal (``comm="bash"``, ``name="/tmp/x"``);
- unquoted values that look like even-length hex in *content* fields are
  audited hex-encoded bytes (EXECVE ``aN`` args, PROCTITLE, PATH ``name``);
- SYSCALL ``a0..a3`` are numeric arguments printed in hex notation and are
  never decoded;
- a record whose value does not fit one line continues on the next line(s)
  without a ``type=`` prefix.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

_MSG_RE = re.compile(r"msg=audit\((\d+)(?:\.(\d+))?:(\d+)\)")
_TYPE_RE = re.compile(r"type=(\S+)")
_HEX_VALUE_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")

_HEX_EXACT_FIELDS = {"proctitle"}
_HEX_FIELDS_BY_TYPE = {"EXECVE": ("a",), "PATH": ("name",)}


@dataclass(frozen=True)
class AuditRecord:
    type: str
    fields: dict[str, str]
    raw: str


@dataclass(frozen=True)
class AuditEvent:
    serial: str
    timestamp: float
    records: tuple[AuditRecord, ...]

    def of_type(self, record_type: str) -> list[AuditRecord]:
        return [record for record in self.records if record.type == record_type]

    def first(self, record_type: str) -> AuditRecord | None:
        for record in self.records:
            if record.type == record_type:
                return record
        return None

    def field(self, name: str) -> str | None:
        """First occurrence of a field across the event's records."""
        for record in self.records:
            value = record.fields.get(name)
            if value is not None:
                return value
        return None

    def audit_keys(self) -> tuple[str, ...]:
        record = self.first("SYSCALL")
        raw = (record.fields.get("key") if record else "") or ""
        if raw.strip() in ("", "(null)"):
            return ()
        return tuple(key.strip() for key in raw.split(",") if key.strip())


def _decode_unquoted(record_type: str, key: str, value: str) -> str:
    hex_field = key in _HEX_EXACT_FIELDS
    if not hex_field:
        prefixes = _HEX_FIELDS_BY_TYPE.get(record_type, ())
        hex_field = (key == "name" and "name" in prefixes) or (
            key.startswith("a") and key[1:].isdigit() and "a" in prefixes)
    if hex_field and len(value) >= 4 and len(value) % 2 == 0 and _HEX_VALUE_RE.match(value):
        try:
            return bytes.fromhex(value).decode("utf-8", "replace")
        except ValueError:
            return value
    return value


def _parse_fields(record_type: str, body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    index, length = 0, len(body)
    while index < length:
        while index < length and body[index] in " \t":
            index += 1
        if index >= length:
            break
        key_start = index
        while index < length and body[index] not in " =\t":
            index += 1
        if index >= length:
            break
        if body[index] != "=":
            continue
        key = body[key_start:index]
        index += 1
        if index < length and body[index] == '"':
            index += 1
            buffer: list[str] = []
            while index < length:
                char = body[index]
                if char == "\\" and index + 1 < length:
                    buffer.append(body[index + 1])
                    index += 2
                    continue
                if char == '"':
                    index += 1
                    break
                buffer.append(char)
                index += 1
            fields[key] = "".join(buffer)
            continue
        value_start = index
        while index < length and body[index] not in " \t":
            index += 1
        fields[key] = _decode_unquoted(record_type, key, body[value_start:index])
    return fields


class AuditLogParser:
    """Line-oriented parser; ``feed`` returns the events it completed."""

    def __init__(self) -> None:
        self._serial: str | None = None
        self._timestamp = 0.0
        self._records: list[dict[str, str]] = []
        self.lines_ignored = 0

    def feed(self, line: str) -> list[AuditEvent]:
        text = line.rstrip("\r\n")  # tolerate CRLF fixtures/checkouts
        if not text.strip():
            return []
        type_match = _TYPE_RE.match(text)
        if type_match is None:
            # Continuation of the previous record: auditd splits a record's raw
            # text at the line-length boundary, so the chunk is appended verbatim.
            if self._records:
                self._records[-1]["body"] += text
            else:
                self.lines_ignored += 1
            return []
        match = _MSG_RE.search(text)
        if match is None:
            self.lines_ignored += 1
            return []
        serial = match.group(3)
        timestamp = float(f"{match.group(1)}.{match.group(2) or '0'}")

        events: list[AuditEvent] = []
        if self._serial is not None and serial != self._serial:
            events.append(self._flush())
        if self._serial is None:
            self._serial = serial
            self._timestamp = timestamp
        record_type = type_match.group(1)
        self._records.append({"type": record_type, "body": text[match.end():]})
        if record_type == "EOE":
            events.append(self._flush())
        return events

    def flush(self) -> list[AuditEvent]:
        """Emit a still-open group (audit logs do not always end with EOE)."""
        return [self._flush()] if self._serial is not None else []

    def _flush(self) -> AuditEvent:
        records = tuple(AuditRecord(type=item["type"],
                                    fields=_parse_fields(item["type"], item["body"]),
                                    raw=item["body"])
                        for item in self._records)
        event = AuditEvent(serial=self._serial or "", timestamp=self._timestamp,
                           records=records)
        self._serial = None
        self._timestamp = 0.0
        self._records = []
        return event


def parse_lines(lines: Iterable[str]) -> list[AuditEvent]:
    parser = AuditLogParser()
    events: list[AuditEvent] = []
    for line in lines:
        events.extend(parser.feed(line))
    events.extend(parser.flush())
    return events