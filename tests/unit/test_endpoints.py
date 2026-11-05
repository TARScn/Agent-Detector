"""P0-C endpoint identity, bindings and Docker published-port resolution."""
from sqlalchemy.orm import Session

from agent_detector.correlation import DockerPortBinding, DockerPortResolver
from agent_detector.storage.database import make_engine
from agent_detector.storage.endpoint_repository import EndpointRepository


def test_endpoint_key_is_stable_and_scope_sensitive():
    first = EndpointRepository.endpoint_key("host-1", "tcp", "127.0.0.1", 11434)
    same = EndpointRepository.endpoint_key("host-1", "tcp", "127.0.0.1", 11434)
    other_port = EndpointRepository.endpoint_key("host-1", "tcp", "127.0.0.1", 11435)
    other_scope = EndpointRepository.endpoint_key("host-2", "tcp", "127.0.0.1", 11434)
    assert first == same
    assert first != other_port
    assert first != other_scope
    assert first.startswith("ep-")


def test_endpoint_repository_binds_host_to_container(tmp_path):
    engine = make_engine(tmp_path / "db.sqlite3")
    with Session(engine) as session:
        repo = EndpointRepository(session)
        host = repo.upsert_endpoint("host-1", "tcp", "127.0.0.1", 11434)
        container = repo.upsert_endpoint("host-1", "tcp", "0.0.0.0", 11434,
                                         namespace="container:abc")
        first = repo.bind(host, container, "abc")
        second = repo.bind(host, container, "abc")  # idempotent open binding
        assert first == second
        binding = repo.get_binding(host)
        assert binding is not None
        assert binding.container_id == "abc"
        assert binding.container_endpoint_id == container
        session.commit()


def test_docker_port_resolver_matches_wildcard_and_specific(capsys):
    calls = {"n": 0}

    def loader():
        calls["n"] += 1
        return [
            DockerPortBinding("cid-wild", 11434, "0.0.0.0", 11434),
            DockerPortBinding("cid-local", 8080, "127.0.0.1", 8080),
        ]

    resolver = DockerPortResolver(loader=loader, cache_seconds=60)
    assert resolver.resolve("127.0.0.1", 11434).container_id == "cid-wild"
    assert resolver.resolve("127.0.0.1", 8080).container_id == "cid-local"
    assert resolver.resolve("127.0.0.1", 9999) is None
    # one load serves all lookups inside the TTL
    assert calls["n"] == 1


def test_docker_port_resolver_disabled_is_null():
    resolver = DockerPortResolver(
        loader=lambda: [DockerPortBinding("cid", 11434, "0.0.0.0", 11434)],
        enabled=False)
    assert resolver.resolve("127.0.0.1", 11434) is None