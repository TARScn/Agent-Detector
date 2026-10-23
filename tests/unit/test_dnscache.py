import json
from types import SimpleNamespace

from agent_detector.monitoring.collectors.host import dns_cache as dnscache
from agent_detector.monitoring.collectors.host.dns_cache import DnsCache, parse_dns_cache_json

SAMPLE = json.dumps([
    {"Entry": "api.anthropic.com", "Data": "93.184.216.34"},
    {"Entry": "Open.Bigmodel.cn.", "Data": "36.99.35.10"},
    {"Entry": "", "Data": "1.2.3.4"},
    {"Entry": "localhost", "Data": ""},
])


def dump(entry, data):
    return json.dumps([{"Entry": entry, "Data": data}])


def test_parse_array_shape():
    assert parse_dns_cache_json(SAMPLE) == {"93.184.216.34": "api.anthropic.com",
                                            "36.99.35.10": "open.bigmodel.cn"}


def test_parse_single_object_and_garbage():
    single = json.dumps({"Entry": "a.example", "Data": "5.6.7.8"})
    assert parse_dns_cache_json(single) == {"5.6.7.8": "a.example"}
    assert parse_dns_cache_json("") == {}
    assert parse_dns_cache_json("not json at all") == {}
    assert parse_dns_cache_json(None) == {}


def test_ingest_merges_and_keeps_multiple_hosts_per_ip():
    cache = DnsCache()
    cache._ingest(dump("api.anthropic.com", "1.2.3.4"))
    cache._ingest(json.dumps([{"Entry": "api.openai.com", "Data": "1.2.3.4"},
                              {"Entry": "open.bigmodel.cn.", "Data": "5.6.7.8"}]))
    snapshot = cache.snapshot()
    assert {h for h, _o in snapshot["1.2.3.4"]} == {"api.anthropic.com", "api.openai.com"}
    assert snapshot["5.6.7.8"] == (("open.bigmodel.cn", "cache"),)
    assert cache.entry_count == 3


def test_merge_proactive_records_probe_origin():
    cache = DnsCache()
    cache._ingest(dump("api.anthropic.com", "1.2.3.4"))
    cache.merge_proactive({"5.6.7.8": "token-plan.cn-beijing.maas.aliyuncs.com"})
    snapshot = cache.snapshot()
    assert snapshot["1.2.3.4"] == (("api.anthropic.com", "cache"),)
    assert snapshot["5.6.7.8"] == (("token-plan.cn-beijing.maas.aliyuncs.com", "probe"),)


def test_ingest_ignores_garbage_lines():
    cache = DnsCache()
    cache._ingest("")
    cache._ingest("{not json")
    assert cache.snapshot() == {}


def test_retention_purges_stale_entries():
    import time
    cache = DnsCache(retention_seconds=0.0)
    cache._ingest(dump("old.example", "9.9.9.9"))
    time.sleep(0.01)
    assert cache.snapshot() == {}
    assert cache.entry_count == 0


def test_start_close_lifecycle(monkeypatch):
    fake_proc = SimpleNamespace(stdout=iter([]), terminate=lambda: None,
                                wait=lambda timeout=None: 0, kill=lambda: None)
    monkeypatch.setattr(dnscache.subprocess, "Popen", lambda *a, **k: fake_proc)
    cache = DnsCache()
    cache.start()
    cache.close()
    assert cache.running is False


def test_start_degrades_off_windows(monkeypatch):
    monkeypatch.setattr(dnscache.sys, "platform", "linux")
    cache = DnsCache()
    cache.start()
    assert cache.failed is True and cache.running is False
    assert cache.snapshot() == {}