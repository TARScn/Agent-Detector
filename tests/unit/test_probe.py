from agent_detector.domain.models import HostFacts, ListeningSocket
from agent_detector.probes.http import is_local, probe_facts


def test_local_guard():
    assert is_local("127.0.0.1") and is_local("::1")
    assert not is_local("8.8.8.8") and not is_local("example.com")


def test_probe_skips_when_no_local_listeners():
    assert probe_facts(HostFacts("h", (), ()), max_probes=5) == []


def test_probe_ignores_remote_bound_listeners():
    facts = HostFacts("h", (), (ListeningSocket("192.168.1.5", 8000, None),))
    assert probe_facts(facts, max_probes=5) == []
