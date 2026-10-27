"""dockerapi 传输层：读门槛（allow/deny）、归档读取与封顶、top 解析。

全部用注入的 fake client（内存 tar），不依赖真实 Docker daemon。
"""
from __future__ import annotations

import io
import tarfile

from agent_detector.discovery.sources import dockerapi
from agent_detector.discovery.sources.dockerapi import TopProcess, path_denied, read_allowed


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


class FakeAPIClient:
    """docker-py APIClient 的最小假件：只实现 dockerapi 用到的四个调用。

    缺失的 archive/top 用 KeyError 模拟 docker.errors.NotFound——dockerapi
    对这些一律按"不存在"降级。
    """

    def __init__(self, containers=None, tops=None, inspects=None, archives=None,
                 busybox=()):
        self.container_list = containers or []
        self.tops = tops or {}
        self.inspects = inspects or {}
        self.archives = archives or {}  # (container_id, path) -> bytes | stream
        self.archive_calls: list[tuple[str, str]] = []
        self.busybox = set(busybox)     # 容器内是 busybox ps：不支持 -eo

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


def test_probe_path_closes_stream_after_first_chunk():
    stream = CloseableStream([b"x" * 512, b"y" * 512])
    client = FakeAPIClient(archives={("c1", "/usr/local/lib"): stream})
    assert dockerapi.probe_path(client, "c1", "/usr/local/lib")
    assert stream.closed  # 存在性检查只读一个块，立刻断流


# ---------------------------------------------------------------------------
# 依赖元数据枚举（目录归档流式扫描）
# ---------------------------------------------------------------------------

def test_iter_dist_metadata_enumerates_and_aborts_when_interest_satisfied():
    tar = make_tar({
        "site-packages/langgraph-0.2.6.dist-info/METADATA":
            "Metadata-Version: 2.1\nName: langgraph\nVersion: 0.2.6\n\ndocs...",
        "site-packages/zlib-1.0.dist-info/METADATA": "Name: zlib\nVersion: 1.0\n",
    })
    client = FakeAPIClient(archives={("c1", "/sp"): iter([tar])})
    found = list(dockerapi.iter_dist_metadata(
        client, "c1", "/sp", interest={"langgraph"}, byte_cap=1 << 20, time_cap=10))
    assert [item[:2] for item in found] == [("langgraph", "0.2.6")]
    # 兴趣集命中即提前断流：排在后面的 zlib 不再读取
    assert len(found) == 1


def test_iter_dist_metadata_byte_cap_stops_without_error():
    tar = make_tar({
        f"site-packages/pkg{i}-1.0.dist-info/METADATA": f"Name: pkg{i}\nVersion: 1.0\n"
        for i in range(20)})
    client = FakeAPIClient(archives={("c1", "/sp"): iter([tar])})
    found = list(dockerapi.iter_dist_metadata(
        client, "c1", "/sp", interest=set(), byte_cap=64, time_cap=10))
    assert found == []


def test_iter_dist_metadata_missing_directory_is_empty():
    client = FakeAPIClient()
    assert list(dockerapi.iter_dist_metadata(
        client, "c1", "/nope", interest={"x"}, byte_cap=1024, time_cap=5)) == []


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
