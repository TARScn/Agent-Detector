from agent_detector.monitoring.detection.attribution import AgentAttributor
from agent_detector.monitoring.detection.process_graph import ProcessGraph
from agent_detector.core.enums import AssetType
from agent_detector.core.models import ProcessInfo
from agent_detector.discovery.fingerprints.schema import ClientRule, ProcessSpec
from agent_detector.core.identity import build_asset_id, normalize_path


def offline_graph(*processes):
    graph = ProcessGraph(live_lookup=lambda pid: None)
    graph.seed(processes)
    return graph


def agent_tree():
    return (
        ProcessInfo(pid=100, name="claude", cmdline=("claude",),
                    create_time=1.0, ppid=1),
        ProcessInfo(pid=200, name="bash", cmdline=("bash", "-c", "x"),
                    create_time=2.0, ppid=100),
        ProcessInfo(pid=300, name="python3", cmdline=("python3", "t.py"),
                    create_time=3.0, ppid=200),
    )


def test_grandchild_attributed_through_asset_pid_map():
    attributor = AgentAttributor(hostname="host", graph=offline_graph(*agent_tree()),
                                 pid_map={100: "claude-code--abc"},
                                 known_asset_ids={"claude-code--abc"})
    result = attributor.attribute(pid=300, ppid=200, process_name="python3")
    assert result.asset_id == "claude-code--abc"
    assert result.evidence == ("ancestor_asset_pid",)
    assert result.ancestor_pid == 100
    assert result.agent_label == "claude"


def test_actor_itself_in_pid_map_is_tagged_self():
    attributor = AgentAttributor(hostname="host", graph=offline_graph(*agent_tree()),
                                 pid_map={100: "claude-code--abc"},
                                 known_asset_ids={"claude-code--abc"})
    result = attributor.attribute(pid=100, ppid=1, process_name="claude")
    assert result.evidence == ("self_asset_pid",)
    assert result.ancestor_pid == 100


def test_reused_actor_pid_rejects_snapshot_match():
    """Identity gate: the fact's start instant contradicts the registry node
    (pid reused since the snapshot) — the snapshot asset pinned to that pid
    must not claim the fact, and nothing about the live process applies."""
    graph = offline_graph(ProcessInfo(pid=70, name="node", cmdline=("node", "cli.js"),
                                      create_time=50.0, ppid=1))
    attributor = AgentAttributor(hostname="host", graph=graph,
                                 pid_map={70: "stale--asset"},
                                 known_asset_ids={"stale--asset"})
    rejected = attributor.attribute(pid=70, ppid=1, process_name="node",
                                    start_time=100.0)
    assert rejected.asset_id is None
    assert rejected.evidence == ("unattributed",)
    # verified identity: the match stands
    verified = attributor.attribute(pid=70, ppid=1, process_name="node",
                                    start_time=51.0)
    assert verified.asset_id == "stale--asset"
    assert verified.evidence == ("self_asset_pid",)
    # no identity info on either side: legacy trust (Windows channels)
    legacy = attributor.attribute(pid=70, ppid=1, process_name="node")
    assert legacy.asset_id == "stale--asset"


def test_fingerprint_match_links_existing_candidate_asset(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    rule = ClientRule(kind="client_rule", id="demo-agent", name="Demo Agent",
                      asset_type=AssetType.AGENT_CLIENT,
                      process=ProcessSpec(executable_names=["demo-agent"]))
    candidate = build_asset_id("host", "demo-agent",
                               f"user-home:{normalize_path(home)}")
    graph = offline_graph(
        ProcessInfo(pid=50, name="demo-agent", cmdline=("demo-agent", "run"),
                    create_time=1.0, ppid=1),
        ProcessInfo(pid=60, name="python3", cmdline=("python3", "x.py"),
                    create_time=2.0, ppid=50))
    attributor = AgentAttributor(hostname="host", graph=graph, pid_map={},
                                 known_asset_ids={candidate}, client_rules=[rule],
                                 home=home)
    result = attributor.attribute(pid=60, ppid=50, process_name="python3")
    assert result.agent_label == "Demo Agent"
    assert result.asset_id == candidate
    assert "process_fingerprint" in result.evidence


def test_fingerprint_match_without_stored_asset_keeps_asset_id_empty(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    rule = ClientRule(kind="client_rule", id="demo-agent", name="Demo Agent",
                      asset_type=AssetType.AGENT_CLIENT,
                      process=ProcessSpec(executable_names=["demo-agent"]))
    graph = offline_graph(ProcessInfo(pid=50, name="demo-agent",
                                      cmdline=("demo-agent",), create_time=1.0, ppid=1))
    attributor = AgentAttributor(hostname="host", graph=graph, pid_map={},
                                 known_asset_ids=set(), client_rules=[rule], home=home)
    result = attributor.attribute(pid=50, ppid=1, process_name="demo-agent")
    assert result.agent_label == "Demo Agent" and result.asset_id is None
    assert result.evidence[0] == "process_fingerprint"


def test_unmatched_process_is_unattributed():
    attributor = AgentAttributor(hostname="host",
                                 graph=offline_graph(ProcessInfo(pid=9, name="vi",
                                                                 cmdline=("vi",),
                                                                 create_time=1.0, ppid=1)),
                                 pid_map={}, known_asset_ids=set())
    result = attributor.attribute(pid=9, ppid=1, process_name="vi")
    assert result.asset_id is None and result.ancestor_pid is None
    assert result.evidence == ("unattributed",)
    assert result.agent_label == "vi"