import json
from subprocess import TimeoutExpired
from types import SimpleNamespace

from agent_detector.behavior import dnscache
from agent_detector.behavior.dnscache import DnsCache, parse_dns_cache_json

SAMPLE = json.dumps([
    {"Entry": "api.anthropic.com", "Data": "93.184.216.34"},
    {"Entry": "Open.Bigmodel.cn.", "Data": "36.99.35.10"},
    {"Entry": "", "Data": "1.2.3.4"},
    {"Entry": "localhost", "Data": ""},
])


def test_parse_array_shape():
    assert parse_dns_cache_json(SAMPLE) == {"93.184.216.34": "api.anthropic.com",
                                            "36.99.35.10": "open.bigmodel.cn"}


def test_parse_single_object_and_garbage():
    single = json.dumps({"Entry": "a.example", "Data": "5.6.7.8"})
    assert parse_dns_cache_json(single) == {"5.6.7.8": "a.example"}
    assert parse_dns_cache_json("") == {}
    assert parse_dns_cache_json("not json at all") == {}
    assert parse_dns_cache_json(None) == {}


def test_snapshot_reads_powershell(monkeypatch):
    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=SAMPLE, stderr="")
    monkeypatch.setattr(dnscache.subprocess, "run", fake_run)
    cache = DnsCache(refresh_seconds=999)
    mapping = cache.snapshot()
    assert mapping["93.184.216.34"] == "api.anthropic.com"
    assert cache.failed is False
    # throttled: second call does not re-run the command
    monkeypatch.setattr(dnscache.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("refetch")))
    assert cache.snapshot() is mapping


def test_snapshot_degrades_on_failure(monkeypatch):
    def fake_run(*args, **kwargs):
        raise TimeoutExpired("powershell", 10)
    monkeypatch.setattr(dnscache.subprocess, "run", fake_run)
    cache = DnsCache()
    assert cache.snapshot() == {} and cache.failed is True


def test_snapshot_empty_off_windows(monkeypatch):
    monkeypatch.setattr(dnscache.sys, "platform", "linux")
    cache = DnsCache(refresh_seconds=0)
    assert cache.snapshot() == {}
