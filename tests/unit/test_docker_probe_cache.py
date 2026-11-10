"""docker_probe_cache 门面与存储：digest 键、TTL 过期、禁用旁路（无真实 Docker）。

契约：同 image digest ⇒ 内容复用；身份/时间性数据永不缓存；无 digest 或
TTL=0 时门面退化为纯直连且不计统计。
"""
from __future__ import annotations

import base64

from sqlalchemy.orm import Session

from agent_detector.discovery.sources import dockerapi
from agent_detector.discovery.sources.docker_probe_cache import (
    DictProbeCacheStore,
    ProbeCache,
    build_key,
)
from agent_detector.storage.database import make_engine
from agent_detector.storage.docker_probe_cache import (
    DockerProbeCacheRepository,
    probe_cache_key,
)
from agent_detector.storage.models import DockerProbeCacheRow

DIGEST = "sha256:" + "c" * 64


def test_probe_and_read_are_cached_until_invalidated(monkeypatch):
    probes: list[str] = []
    reads: list[str] = []
    monkeypatch.setattr(dockerapi, "probe_path",
                        lambda client, cid, path: probes.append(path) or True)
    monkeypatch.setattr(dockerapi, "read_container_file",
                        lambda client, cid, path, max_bytes:
                        reads.append(path) or b"data")
    cache = ProbeCache(DictProbeCacheStore(), engine_key="local",
                       image_id=DIGEST, container_id="c1")
    assert cache.probe_path(None, "c1", "/app/pyproject.toml") is True
    assert cache.probe_path(None, "c1", "/app/pyproject.toml") is True
    assert cache.read_file(None, "c1", "/app/uv.lock", 4096) == b"data"
    assert cache.read_file(None, "c1", "/app/uv.lock", 4096) == b"data"
    # 第二次全部走缓存：底层各只调一次
    assert probes == ["/app/pyproject.toml"]
    assert reads == ["/app/uv.lock"]
    assert cache.stats == {"hits": 2, "misses": 2, "stores": 2}


def test_read_not_found_is_cached_too(monkeypatch):
    reads: list[str] = []
    monkeypatch.setattr(dockerapi, "read_container_file",
                        lambda client, cid, path, max_bytes:
                        reads.append(path) or None)
    cache = ProbeCache(DictProbeCacheStore(), engine_key="local",
                       image_id=DIGEST, container_id="c1")
    assert cache.read_file(None, "c1", "/app/nope.toml", 4096) is None
    assert cache.read_file(None, "c1", "/app/nope.toml", 4096) is None
    assert reads == ["/app/nope.toml"]


def test_expired_store_entry_reprobes(monkeypatch):
    probes: list[str] = []
    monkeypatch.setattr(dockerapi, "probe_path",
                        lambda client, cid, path: probes.append(path) or True)
    store = DictProbeCacheStore()
    cache = ProbeCache(store, engine_key="local", image_id=DIGEST,
                       container_id="c1", ttl_s=50)
    assert cache.probe_path(None, "c1", "/x") is True
    key = build_key("local", DIGEST, "probe", "/x")
    store.rows[key]["probed_at"] -= 100  # 把条目拨回 TTL 之外
    assert cache.probe_path(None, "c1", "/x") is True
    assert probes == ["/x", "/x"]


def test_dist_metadata_roundtrips_through_the_cache(monkeypatch):
    calls = {"n": 0}
    member = "site-packages/langgraph-0.2.6.dist-info/METADATA"

    def fake_iter(client, cid, site, *, interest, byte_cap, time_cap,
                  stall_grace=None):
        calls["n"] += 1
        return [("langgraph", "0.2.6", member)]

    monkeypatch.setattr(dockerapi, "iter_dist_metadata", fake_iter)
    cache = ProbeCache(DictProbeCacheStore(), engine_key="local",
                       image_id=DIGEST, container_id="c1")
    first = cache.iter_dist_metadata(None, "c1", "/sp", interest={"langgraph"},
                                     byte_cap=1000, time_cap=5)
    second = cache.iter_dist_metadata(None, "c1", "/sp", interest={"langgraph"},
                                      byte_cap=1000, time_cap=5)
    assert first == second == [("langgraph", "0.2.6", member)]
    assert calls["n"] == 1
    # 兴趣集参与键：换个兴趣表就是一次新探测
    cache.iter_dist_metadata(None, "c1", "/sp", interest={"langchain"},
                             byte_cap=1000, time_cap=5)
    assert calls["n"] == 2


def test_disabled_facade_is_passthrough(monkeypatch):
    probes: list[str] = []
    monkeypatch.setattr(dockerapi, "probe_path",
                        lambda client, cid, path: probes.append(path) or True)
    # 无 store / 无 digest / TTL=0 三种旁路
    for cache in (ProbeCache(None, engine_key="", image_id="",
                             container_id="c1"),
                  ProbeCache(DictProbeCacheStore(), engine_key="local",
                             image_id="", container_id="c1"),
                  ProbeCache(DictProbeCacheStore(), engine_key="local",
                             image_id=DIGEST, container_id="c1", ttl_s=0)):
        assert cache.probe_path(None, "c1", "/x") is True
        assert cache.probe_path(None, "c1", "/x") is True
        assert cache.stats == {}
    assert probes == ["/x"] * 6


def test_repository_roundtrip_ttl_and_upsert(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    spec = "/app/pyproject.toml|4096"
    key = probe_cache_key("local", DIGEST, "read", spec)
    payload = {"found": True,
               "content_b64": base64.b64encode(b"data").decode("ascii")}
    with Session(engine) as session:
        repo = DockerProbeCacheRepository(session)
        assert repo.lookup(key, ttl_s=3600) is None
        repo.save(key, engine_key="local", image_id=DIGEST, kind="read",
                  spec=spec, payload=payload)
        assert repo.lookup(key, ttl_s=3600) == payload
        # TTL 过期：拨回 probed_at
        row = session.get(DockerProbeCacheRow, key)
        row.probed_at = "2000-01-01T00:00:00+00:00"
        session.flush()
        assert repo.lookup(key, ttl_s=3600) is None
        # now 显式给在 TTL 窗口内：命中
        assert repo.lookup(key, ttl_s=3600,
                           now="2000-01-01T00:00:30+00:00") == payload
        # 覆盖写：同键更新 payload 与时间戳
        repo.save(key, engine_key="local", image_id=DIGEST, kind="read",
                  spec=spec, payload={"found": False, "content_b64": ""})
        assert repo.lookup(key, ttl_s=3600) == {"found": False,
                                                "content_b64": ""}
