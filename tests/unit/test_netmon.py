from types import SimpleNamespace

import psutil

from agent_detector.behavior.netmon import (ConnInfo, collect_outbound, is_loopback_ip,
                                            match_llm_call, resolve_process_names)
from agent_detector.behavior.rules import load_rules


def sock(status, ip, port, pid):
    return SimpleNamespace(status=status, raddr=SimpleNamespace(ip=ip, port=port), pid=pid)


def test_collect_outbound_filters_established_with_pid(monkeypatch):
    rows = [sock(psutil.CONN_ESTABLISHED, "93.184.216.34", 443, 4242),
            sock(psutil.CONN_LISTEN, "0.0.0.0", 8000, 4242),
            sock(psutil.CONN_ESTABLISHED, "93.184.216.34", 443, None),
            SimpleNamespace(status=psutil.CONN_ESTABLISHED, raddr=None, pid=4242)]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="tcp": rows)
    conns = collect_outbound()
    assert [(c.pid, c.remote_ip, c.remote_port) for c in conns] == \
        [(4242, "93.184.216.34", 443)]


def test_collect_outbound_swallows_access_denied(monkeypatch):
    def boom(kind="tcp"):
        raise psutil.AccessDenied("nope")
    monkeypatch.setattr(psutil, "net_connections", boom)
    assert collect_outbound() == []


def test_match_llm_api_via_dns_cache():
    rules = load_rules().rules
    conn = ConnInfo(pid=4242, process_name="claude.exe",
                    remote_ip="93.184.216.34", remote_port=443)
    hit = match_llm_call(conn, rules, {"93.184.216.34": "api.anthropic.com"})
    assert hit is not None
    assert (hit.match_kind, hit.host, hit.confidence) == ("llm_api", "api.anthropic.com", "medium")
    assert hit.evidence == ("dns_cache", "known_llm_host")


def test_match_local_model_port_on_loopback():
    rules = load_rules().rules
    conn = ConnInfo(pid=99, process_name="my-agent.exe", remote_ip="127.0.0.1", remote_port=11434)
    hit = match_llm_call(conn, rules, {})
    assert hit is not None
    assert (hit.match_kind, hit.host) == ("local_model", "Ollama:11434")
    assert hit.evidence == ("local_model_port",)


def test_no_match_without_dns_or_known_port():
    rules = load_rules().rules
    remote = ConnInfo(pid=1, process_name="x", remote_ip="1.2.3.4", remote_port=443)
    assert match_llm_call(remote, rules, {}) is None
    assert match_llm_call(remote, rules, {"1.2.3.4": "example.com"}) is None
    loopback_unknown = ConnInfo(pid=1, process_name="x", remote_ip="127.0.0.1", remote_port=9999)
    assert match_llm_call(loopback_unknown, rules, {}) is None


def test_dns_name_not_in_rules_is_ignored():
    rules = load_rules().rules
    conn = ConnInfo(pid=1, process_name="x", remote_ip="1.2.3.4", remote_port=443)
    assert match_llm_call(conn, rules, {"1.2.3.4": "cdn.example.com"}) is None


def test_is_loopback_ip():
    assert is_loopback_ip("127.0.0.1") and is_loopback_ip("::1")
    assert not is_loopback_ip("8.8.8.8") and not is_loopback_ip("not-an-ip")


def test_resolve_process_names_current_process():
    import os
    names = resolve_process_names({os.getpid()})
    assert names[os.getpid()].lower().startswith("python")
