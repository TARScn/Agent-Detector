"""Sysmon parsing and fact mapping (design section 4.1).

The subscription itself needs a Windows host with Sysmon installed, so the
tests cover the pure half: XML -> SysmonEvent -> BehaviorFact, plus the
availability check telling the truth on a host without Sysmon.
"""
from __future__ import annotations

import sys

import pytest

from agent_detector.monitoring.collectors.host.sysmon import (SUPPORTED_EVENTS, SysmonEvent,
                                              fact_from_event, parse_event_xml,
                                              split_command_line, sysmon_available)

PROCESS_CREATE = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>
  <EventID>1</EventID>
  <TimeCreated SystemTime="2026-10-20T09:40:00.1234567Z"/>
 </System>
 <EventData>
  <Data Name="ProcessGuid">{a1b2}</Data>
  <Data Name="ProcessId">3224</Data>
  <Data Name="Image">C:\\Program Files\\nodejs\\node.exe</Data>
  <Data Name="CommandLine">node "C:\\Users\\u\\cli.js" --resume</Data>
  <Data Name="ParentProcessId">1024</Data>
  <Data Name="UtcTime">2026-10-20 09:40:00.123</Data>
 </EventData>
</Event>"""

FILE_DELETE = PROCESS_CREATE.replace("<EventID>1</EventID>", "<EventID>23</EventID>").replace(
    '<Data Name="CommandLine">node "C:\\Users\\u\\cli.js" --resume</Data>',
    '<Data Name="TargetFilename">D:\\ImportantData\\report.docx</Data>')

NETWORK_CONNECT = PROCESS_CREATE.replace("<EventID>1</EventID>", "<EventID>3</EventID>").replace(
    '<Data Name="CommandLine">node "C:\\Users\\u\\cli.js" --resume</Data>',
    "<Data Name=\"CommandLine\">powershell -c Invoke-WebRequest</Data>\n"
    '  <Data Name="DestinationIp">93.184.216.34</Data>\n'
    '  <Data Name="DestinationPort">443</Data>\n'
    '  <Data Name="DestinationHostname">api.anthropic.com</Data>')


def test_process_create_becomes_an_exec_fact():
    event = parse_event_xml(PROCESS_CREATE)
    assert isinstance(event, SysmonEvent)
    assert event.event_id == 1 and event.name == "process.create"
    assert event.process_name == "node.exe"
    assert event.pid == 3224 and event.ppid == 1024
    assert event.ts > 0  # UtcTime parsed from the Sysmon format

    fact = fact_from_event(event)
    assert fact.kind == "proc.exec"
    assert fact.argv[0] == "node" and fact.argv[-1] == "--resume"
    assert "sysmon" in fact.evidence
    assert any(item.startswith("process_guid:") for item in fact.evidence)


def test_file_delete_becomes_a_delete_fact_with_its_target():
    fact = fact_from_event(parse_event_xml(FILE_DELETE))
    assert fact.kind == "file.delete"
    assert fact.path == "D:\\ImportantData\\report.docx"


def test_network_connect_keeps_endpoint_and_hostname():
    fact = fact_from_event(parse_event_xml(NETWORK_CONNECT))
    assert fact.kind == "net.connect"
    assert fact.endpoint == "93.184.216.34:443"
    assert "host:api.anthropic.com" in fact.evidence


def test_unsupported_and_foreign_events_are_ignored():
    assert parse_event_xml(FILE_DELETE.replace("<EventID>23</EventID>",
                                               "<EventID>7</EventID>")) is None
    foreign = PROCESS_CREATE.replace("Microsoft-Windows-Sysmon", "Some-Other-Provider")
    assert parse_event_xml(foreign) is None
    assert parse_event_xml("<not-xml") is None
    assert parse_event_xml("<Event><System></System></Event>") is None


def test_events_without_a_process_id_produce_no_fact():
    xml = PROCESS_CREATE.replace('<Data Name="ProcessId">3224</Data>', "")
    event = parse_event_xml(xml)
    assert event is not None and event.pid is None
    assert fact_from_event(event) is None


@pytest.mark.parametrize("event_id", list(SUPPORTED_EVENTS))
def test_every_supported_event_id_parses(event_id):
    xml = PROCESS_CREATE.replace("<EventID>1</EventID>", f"<EventID>{event_id}</EventID>")
    assert parse_event_xml(xml) is not None


def test_command_line_splitting_honours_quotes():
    assert split_command_line('rm -rf "C:/x y/z" --flag') == (
        "rm", "-rf", "C:/x y/z", "--flag")
    assert split_command_line("") == ()


def test_availability_is_honest_about_the_host():
    status = sysmon_available()
    assert isinstance(status.available, bool)
    if sys.platform != "win32":
        assert status.available is False
        assert "非 Windows" in status.reason
    else:
        # Either Sysmon is readable, or the reason says why it is not.
        assert status.available or status.reason