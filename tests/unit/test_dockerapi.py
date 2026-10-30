"""dockerapi 传输层：读门槛（allow/deny）、stat 预检、归档读取与封顶、top 解析。

全部用注入的 fake client（内存 tar），不依赖真实 Docker daemon。
"""
from __future__ import annotations

import base64
import io
import json
import tarfile
import time

import pytest

from agent_detector.discovery.sources import dockerapi
from agent_detector.discovery.sources.dockerapi import (TopProcess, path_denied,
                                                        read_allowed)


def make_tar(entries: dict[str, bytes | str | None]) -> bytes:
    """Build an in-memory tar: name -> content (None = directory)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in entries.items():
            if content is None:
                info = tarfile.TarInfo(name.rstrip("/") + "/")
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
                continue
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class CloseableStream:
    """Chunked archive stream that records close() — early-abort assertions."""

    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._chunks)

    def close(self):
        self.closed = True


class SleepingStream(CloseableStream):
    """每个块之前停顿 delay 秒：模拟 npipe 上 daemon 响应卡死
    （socket 超时不生效、读永远不返回的生产故障形态）。"""

    def __init__(self, delay, chunks=(b"x",)):
        super().__init__(chunks)
        self._delay = delay

    def __next__(self):
        time.sleep(self._delay)
        return next(self._chunks)


class HeadResponse:
    """HEAD /archive 的最小应答：状态码 + 头。"""

    def __init__(self, status_code, headers):
        self.status_code = status_code
        self.headers = headers


class FakeAPIClient:
    """docker-py APIClient 的最小假件：只实现 dockerapi 用到的调用。

    缺失的 archive/top/stat 用 KeyError/404 模拟 docker.errors.NotFound
    ——dockerapi 对这些一律按"不存在"降级。
    """

    def __init__(self, containers=None, tops=None, inspects=None, archives=None,
                 busybox=(), stats=None):
        self.container_list = containers or []
        self.tops = tops or {}
        self.inspects = inspects or {}
        self.archives = archives or {}  # (container_id, path) -> bytes | stream
        self.archive_calls: list[tuple[str, str]] = []
        self.busybox = set(busybox)     # 容器内是 busybox ps：不支持 -eo
        self.stats = stats or {}        # (container_id, path) -> stat 覆盖值

    def _url(self, pathfmt, *args):
        return pathfmt.format(*args)

    def head(self, url, params=None, timeout=None):
        container_id = str(url).split("/containers/")[1].split("/", 1)[0]
        path = (params or {}).get("path")
        if (container_id, path) not in self.archives:
            return HeadResponse(404, {})
        payload = self.archives[(container_id, path)]
        size = len(payload) if isinstance(payload, bytes) else 4096
        stat = {"size": size, "mode": 0o100644}
        stat.update(self.stats.get((container_id, path), {}))
        encoded = base64.b64encode(json.dumps(stat).encode("utf-8")).decode("ascii")
        return HeadResponse(200, {"x-docker-container-path-stat": encoded})

    def containers(self, all=False, limit=None):
        return self.container_list

    def top(self, container_id, ps_args=None):
        if ps_args and container_id in self.busybox:
            raise KeyError(f"{container_id}: busybox ps has no -eo")
        try:
            return self.tops[container_id]
        except KeyError:
            raise KeyError(container_id)

    def inspect_container(self, container_id):
        return self.inspects.get(container_id, {})

    def get_archive(self, container_id, path):
        self.archive_calls.append((container_id, path))
        try:
            payload = self.archives[(container_id, path)]
        except KeyError:
            raise KeyError(path)
        if isinstance(payload, bytes):
            return iter([payload]), {"name": path}
        return payload, {"name": path}


# ---------------------------------------------------------------------------
# 读门槛
# ---------------------------------------------------------------------------

def test_read_allowlist_covers_manifests_and_metadata():
    assert read_allowed("/app/pyproject.toml")
    assert read_allowed("/srv/requirements-dev.txt")
    assert read_allowed("/app/uv.lock")
    assert read_allowed("/app/package.json")
    assert read_allowed("/app/package-lock.json")
    assert read_allowed("/usr/local/lib/python3.11/site-packages/"
                        "langgraph-0.2.6.dist-info/METADATA")
    assert read_allowed("/app/node_modules/@scope/pkg/package.json")
    assert read_allowed("/root/.openclaw/openclaw.json")
    assert read_allowed("/root/.claude/settings.json")


def test_read_denylist_blocks_secrets_even_over_allowlist_shapes():
    assert not read_allowed("/app/.env")
    assert not read_allowed("/run/secrets/api_key")
    assert not read_allowed("/root/.ssh/id_rsa")
    assert not read_allowed("/etc/pki/ca.pem")
    assert not read_allowed("/app/server.key")
    assert not read_allowed("/home/u/.git/config")
    # 误伤可接受（宁拒勿读）：token 片段连 tokenizers 的元数据一起挡掉
    assert not read_allowed("/app/node_modules/tokenizers/package.json")
    assert path_denied("/run/secrets/db_password")


def test_probe_path_is_gated_by_denylist_only():
    # 目录探测不受文件名 allowlist 限制（目录永远过不了 allowlist），
    # 但秘密路径的存在性同样不允许探测。
    client = FakeAPIClient(archives={("c1", "/usr/local/lib"): iter([b"x"])})
    assert dockerapi.probe_path(client, "c1", "/usr/local/lib")
    assert not dockerapi.probe_path(client, "c1", "/run/secrets")


def test_stat_path_parses_head_and_404_is_none():
    client = FakeAPIClient(archives={("c1", "/app"): iter([b"x"])},
                           stats={("c1", "/app"): {"size": 123, "mode": 0o40755}})
    stat = dockerapi.stat_path(client, "c1", "/app")
    assert stat == {"size": 123, "mode": 0o40755}
    assert dockerapi.stat_path(client, "c1", "/nope") is None
    # 秘密路径的存在性不可探测
    assert dockerapi.stat_path(client, "c1", "/run/secrets/api_key") is None


# ---------------------------------------------------------------------------
# 归档读取
# ---------------------------------------------------------------------------

def test_read_container_file_roundtrip():
    client = FakeAPIClient(archives={
        ("c1", "/app/pyproject.toml"):
            make_tar({"/app/pyproject.toml": "[project]\nname = 'x'\n"})})
    raw = dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 262144)
    assert raw is not None and b"[project]" in raw


def test_read_container_file_missing_is_none():
    client = FakeAPIClient()
    assert dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 1024) is None


def test_read_container_file_denied_is_none_even_if_present():
    client = FakeAPIClient(archives={("c1", "/app/.env"): make_tar({"/app/.env": "K=V"})})
    assert dockerapi.read_container_file(client, "c1", "/app/.env", 1024) is None


def test_read_container_file_oversized_is_none():
    big = "x" * (300 * 1024)
    client = FakeAPIClient(archives={
        ("c1", "/app/huge.lock"): make_tar({"/app/huge.lock": big})})
    assert dockerapi.read_container_file(client, "c1", "/app/huge.lock", 262144) is None
    assert client.archive_calls == []  # stat 预检拦截，根本不发起 GET/tar


def test_stat_size_gate_applies_before_get():
    # stat 声称很大但归档其实很小：仍按 stat 拦截（GET 不发出）
    client = FakeAPIClient(
        archives={("c1", "/app/uv.lock"): make_tar({"/app/uv.lock": "a = 1\n"})},
        stats={("c1", "/app/uv.lock"): {"size": 10 * 1024 * 1024}})
    assert dockerapi.read_container_file(client, "c1", "/app/uv.lock", 262144) is None
    assert client.archive_calls == []


def test_probe_never_generates_a_tar():
    # probe 走 HEAD stat：哪怕命中也不得发起 GET（GET 的 tar 无法中途安全放弃）
    stream = CloseableStream([b"x" * 512])
    client = FakeAPIClient(archives={("c1", "/usr/local/lib"): stream})
    assert dockerapi.probe_path(client, "c1", "/usr/local/lib")
    assert client.archive_calls == []


# ---------------------------------------------------------------------------
# 依赖元数据枚举（目录归档流式扫描）
# ---------------------------------------------------------------------------

def test_iter_dist_metadata_enumerates_all_within_budget():
    tar = make_tar({
        "site-packages/langgraph-0.2.6.dist-info/METADATA":
            "Metadata-Version: 2.1\nName: langgraph\nVersion: 0.2.6\n\ndocs...",
        "site-packages/zlib-1.0.dist-info/METADATA": "Name: zlib\nVersion: 1.0\n",
    })
    client = FakeAPIClient(archives={("c1", "/sp"): iter([tar])})
    found = dockerapi.iter_dist_metadata(
        client, "c1", "/sp", interest={"langgraph"}, byte_cap=1 << 20, time_cap=10)
    # 归档必须排干到 EOF（中途放弃会在 npipe 上楔死容器）：兴趣集命中也
    # 不再提前断流，zlib 一样被读取
    assert [item[:2] for item in found] == [("langgraph", "0.2.6"), ("zlib", "1.0")]


def test_iter_dist_metadata_skips_when_stat_exceeds_byte_cap():
    # 目录超过字节预算：整个枚举跳过（诚实降级），GET 不发出
    tar = make_tar({
        "site-packages/langgraph-0.2.6.dist-info/METADATA":
            "Name: langgraph\nVersion: 0.2.6\n\n"})
    client = FakeAPIClient(archives={("c1", "/sp"): iter([tar])},
                           stats={("c1", "/sp"): {"size": 512 * 1024 * 1024}})
    found = dockerapi.iter_dist_metadata(
        client, "c1", "/sp", interest={"langgraph"}, byte_cap=1 << 20, time_cap=10)
    assert found == []
    assert client.archive_calls == []


def test_iter_dist_metadata_missing_directory_is_empty():
    client = FakeAPIClient()
    assert dockerapi.iter_dist_metadata(
        client, "c1", "/nope", interest={"x"}, byte_cap=1024, time_cap=5) == []


def test_iter_backstop_trips_but_drains_to_eof():
    """stat 撒谎（实际 tar 超预算）：兜底触发后必须排干到 EOF，不得放弃
    中途流（那会楔死容器的归档通道）；cap 之前解析到的元数据保留。"""
    tar = make_tar({
        "site-packages/langgraph-0.2.6.dist-info/METADATA":
            "Name: langgraph\nVersion: 0.2.6\n\n",
        "site-packages/junk.bin": "x" * 20000,  # 把归档顶过预算
    })
    consumed = {"eof": False}

    class Counting:
        def __init__(self):
            # tarfile 流模式以 RECORDSIZE(10240) 粒度拉流；三段 chunk 让
            # 首拉 22000 字节（预算 24000，剩 2000），第二个成员处触发兜底
            self._it = iter([tar[:4000], tar[4000:22000], tar[22000:]])

        def __iter__(self):
            return self

        def __next__(self):
            try:
                return next(self._it)
            except StopIteration:
                consumed["eof"] = True
                raise

        def close(self):
            pass

    client = FakeAPIClient(archives={("c1", "/sp"): Counting()},
                           stats={("c1", "/sp"): {"size": 4096}})
    found = dockerapi.iter_dist_metadata(client, "c1", "/sp", interest=set(),
                                         byte_cap=24000, time_cap=10)
    assert [item[0] for item in found] == ["langgraph"]
    assert consumed["eof"]


def test_read_stat_lied_drains_and_returns_none():
    stream = CloseableStream([b"x" * (400 * 1024)])  # stat 默认 4096，实际 400KB
    client = FakeAPIClient(archives={("c1", "/app/pyproject.toml"): stream})
    assert dockerapi.read_container_file(
        client, "c1", "/app/pyproject.toml", 262144) is None
    assert stream.closed  # 超限后同样排干到 EOF，不中断流


# ---------------------------------------------------------------------------
# docker top
# ---------------------------------------------------------------------------

def test_container_top_parses_pid_ppid_cmdline():
    client = FakeAPIClient(tops={"c1": {
        "Titles": ["PID", "PPID", "COMMAND"],
        "Processes": [["7", "1", "python /app/server.py"], ["1", "0", "sh"]]}})
    procs = dockerapi.container_top(client, "c1")
    assert procs[0] == TopProcess(7, 1, "python /app/server.py")
    assert procs[1].ppid == 0


def test_container_top_unexpected_titles_degrades_to_empty():
    client = FakeAPIClient(tops={"c1": {"Titles": ["UID"], "Processes": [["x"]]}})
    assert dockerapi.container_top(client, "c1") == []


def test_container_top_falls_back_to_default_ps_on_busybox():
    # alpine/busybox 镜像不支持 -eo：回退 daemon 默认 -ef（UID/PID/PPID/.../CMD）
    client = FakeAPIClient(
        tops={"c1": {"Titles": ["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"],
                     "Processes": [["0", "7", "1", "0", "01:00", "?", "00:00:00",
                                    "python /app/server.py"]]}},
        busybox={"c1"})
    procs = dockerapi.container_top(client, "c1")
    assert procs == [TopProcess(7, 1, "python /app/server.py")]


# ---------------------------------------------------------------------------
# 看门狗：npipe 读超时不生效，靠硬期限放弃卡死的调用
# ---------------------------------------------------------------------------

def watched(client, timeout=0.2, budget=3):
    """给 fake client 挂上 BoundedClient 的鸭子类型属性。"""
    client.timeout = timeout
    client.stall_budget = budget
    client.stalls = 0
    return client


def test_stalled_call_raises_docker_stalled_and_counts():
    client = watched(FakeAPIClient(
        archives={("c1", "/app/pyproject.toml"): SleepingStream(1.0)}))
    start = time.monotonic()
    with pytest.raises(dockerapi.DockerStalled):
        dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 262144)
    assert time.monotonic() - start < 0.8  # 0.2s 期限放弃，不等 1s 的卡死读
    assert client.stalls == 1


def test_breaker_opens_after_budget_and_fails_fast():
    client = watched(FakeAPIClient(
        archives={("c1", "/app/pyproject.toml"): SleepingStream(1.0)}), budget=1)
    with pytest.raises(dockerapi.DockerStalled):
        dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 262144)
    start = time.monotonic()
    with pytest.raises(dockerapi.DockerStalled):
        dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 262144)
    assert time.monotonic() - start < 0.05  # 熔断后立即拒绝，不再起新线程
    assert client.stalls == 1  # 快速失败不计入新的失联


def test_breaker_counts_consecutive_stalls_only():
    # 个别容器楔死不该连坐整条通道：一次成功即清零失联计数
    client = watched(FakeAPIClient(archives={
        ("c1", "/app/pyproject.toml"): SleepingStream(1.0),
        ("c2", "/app/pyproject.toml"): make_tar({"/app/pyproject.toml": "x = 1"}),
    }), budget=3)
    with pytest.raises(dockerapi.DockerStalled):
        dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 262144)
    assert client.stalls == 1
    assert dockerapi.read_container_file(
        client, "c2", "/app/pyproject.toml", 262144) is not None
    assert client.stalls == 0  # 成功清零，预算不被耗尽
    for _ in range(3):  # 连续失联 3 次 → 熔断
        with pytest.raises(dockerapi.DockerStalled):
            dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 262144)
    start = time.monotonic()
    with pytest.raises(dockerapi.DockerStalled):
        dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 262144)
    assert time.monotonic() - start < 0.05


def test_iter_dist_metadata_midstream_stall_hits_watchdog():
    # 内部 time_cap 只在块之间检查：单块读卡死时看门狗是唯一兜底
    tar = make_tar({"site-packages/langgraph-0.2.6.dist-info/METADATA":
                    "Name: langgraph\nVersion: 0.2.6\n\n"})
    client = watched(FakeAPIClient(
        archives={("c1", "/sp"): SleepingStream(1.0, chunks=[tar, b"tail"])}))
    with pytest.raises(dockerapi.DockerStalled):
        dockerapi.iter_dist_metadata(client, "c1", "/sp", interest=set(),
                                     byte_cap=1 << 20, time_cap=0.1,
                                     stall_grace=0.1)


def test_watchdog_delegates_results_and_errors_unchanged():
    # 正常路径：结果原样返回、fake 的异常原样抛出（不是 DockerStalled）
    client = watched(FakeAPIClient(archives={
        ("c1", "/app/pyproject.toml"): make_tar({"/app/pyproject.toml": "x = 1"})}))
    raw = dockerapi.read_container_file(client, "c1", "/app/pyproject.toml", 1024)
    assert raw is not None and b"x = 1" in raw
    with pytest.raises(KeyError):
        dockerapi.list_all_containers(_BrokenLister(), 10)


class _BrokenLister:
    """containers() 直接炸：验证看门狗原样透传操作自身的异常。"""

    timeout = 0.2

    def containers(self, all=False, limit=None):
        raise KeyError("daemon exploded")
