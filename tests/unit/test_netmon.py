from types import SimpleNamespace

import psutil

from agent_detector.behavior.netmon import (ConnInfo, collect_outbound, is_loopback_ip,
                                            match_llm_call, resolve_process_names)
from agent_detector.behavior.rules import load_rules


def sock(status, ip, port, pid):
    return SimpleNamespace(status=status, raddr=SimpleNamespace(ip=ip, port=port), pid=pid)


def conn(ip="93.184.216.34", port=443, pid=4242, name="claude.exe"):
    return ConnInfo(pid=pid, process_name=name, remote_ip=ip, remote_port=port)


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
    hit = match_llm_call(conn(), rules, {"93.184.216.34": ("api.anthropic.com",)})
    assert hit is not None
    assert (hit.match_kind, hit.host, hit.confidence) == ("llm_api", "api.anthropic.com", "medium")
    assert hit.evidence == ("dns_cache", "known_llm_host")


def test_match_llm_api_scans_all_hosts_for_shared_ip():
    rules = load_rules().rules
    shared = {"93.184.216.34": ("cdn.example.com", "api.anthropic.com")}
    hit = match_llm_call(conn(), rules, shared)
    assert hit is not None and hit.host == "api.anthropic.com"


def test_local_model_requires_scan_corroboration():
    rules = load_rules().rules
    call = conn(ip="127.0.0.1", port=11434, pid=777, name="my-agent.exe")
    assert match_llm_call(call, rules, {}) is None
    assert match_llm_call(call, rules, {}, model_ports={}) is None
    hit = match_llm_call(call, rules, {}, model_ports={11434: "ollama--abc123"})
    assert hit is not None
    assert (hit.match_kind, hit.host, hit.asset_id) == ("local_model", "Ollama:11434",
                                                        "ollama--abc123")
    assert hit.evidence == ("local_model_port", "scan_asset")


def test_corroborated_port_outside_rules_is_ignored():
    rules = load_rules().rules
    call = conn(ip="127.0.0.1", port=9999, pid=777, name="x")
    assert match_llm_call(call, rules, {}, model_ports={9999: "some-asset"}) is None


def test_no_match_without_dns_or_known_host():
    rules = load_rules().rules
    remote = conn(ip="1.2.3.4", port=443, pid=1, name="x")
    assert match_llm_call(remote, rules, {}) is None
    assert match_llm_call(remote, rules, {"1.2.3.4": ("cdn.example.com",)}) is None
    # loopback port not in the rules port list at all
    assert match_llm_call(conn(ip="127.0.0.1", port=9999, pid=1, name="x"),
                          rules, {}, model_ports={9999: None}) is None


def test_is_loopback_ip():
    assert is_loopback_ip("127.0.0.1") and is_loopback_ip("::1")
    assert not is_loopback_ip("8.8.8.8") and not is_loopback_ip("not-an-ip")


def test_resolve_process_names_current_process():
    import os
    names = resolve_process_names({os.getpid()})
    assert names[os.getpid()].lower().startswith("python")