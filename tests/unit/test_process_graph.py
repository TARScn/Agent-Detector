from agent_detector.behavior.graph import ProcessGraph
from agent_detector.domain.models import ProcessInfo


def snapshot():
    return [
        ProcessInfo(pid=100, name="codex", cmdline=("codex",), create_time=10.0, ppid=1),
        ProcessInfo(pid=200, name="bash", cmdline=("bash", "-c", "x"),
                    create_time=20.0, ppid=100),
        ProcessInfo(pid=300, name="python3", cmdline=("python3", "t.py"),
                    create_time=30.0, ppid=200),
    ]


def offline_graph(*processes):
    graph = ProcessGraph(live_lookup=lambda pid: None)
    graph.seed(processes or snapshot())
    return graph


def test_ancestors_walk_up_until_parent_is_unknown():
    chain = offline_graph().ancestors_of(300)
    assert [node.pid for node in chain] == [300, 200, 100]
    assert chain[1].name == "bash" and chain[2].name == "codex"


def test_ppid_hint_overrides_stale_link():
    graph = offline_graph(ProcessInfo(pid=500, name="mv", cmdline=("mv",),
                                      create_time=5.0, ppid=999))
    chain = graph.ancestors_of(500, ppid=200)
    assert [node.pid for node in chain] == [500]
    assert chain[0].ppid == 200


def test_unknown_actor_is_synthesized_from_the_hint():
    graph = offline_graph()
    chain = graph.ancestors_of(900, ppid=200)
    assert [node.pid for node in chain] == [900, 200, 100]
    assert chain[0].name == ""  # actor itself was never observed


def test_live_lookup_resolves_reuse_and_fills_gaps():
    live = {77: ProcessInfo(pid=77, name="zsh", cmdline=("zsh",),
                            create_time=7.0, ppid=1)}
    graph = ProcessGraph(live_lookup=lambda pid: live.get(pid))
    graph.seed([ProcessInfo(pid=77, name="stale", cmdline=("stale",),
                            create_time=1.0, ppid=1)])
    node = graph.node(77, verify=True)
    assert node.name == "zsh" and node.create_time == 7.0  # pid reuse detected
    assert graph.node(77).name == "zsh"  # cached afterwards


def test_observe_exec_updates_image_but_keeps_create_time():
    graph = offline_graph(ProcessInfo(pid=42, name="bash", cmdline=("bash",),
                                      create_time=3.0, ppid=7))
    graph.observe_exec(pid=42, ppid=7, name="python3", exe="/usr/bin/python3",
                       argv=("python3", "t.py"))
    node = graph.node(42)
    assert node.name == "python3" and node.exe == "/usr/bin/python3"
    assert node.cmdline == ("python3", "t.py")
    assert node.create_time == 3.0


def test_ancestor_chain_respects_depth_cap_and_cycles():
    graph = offline_graph(*[ProcessInfo(pid=pid, name=f"p{pid}",
                                        create_time=float(pid), ppid=pid - 1)
                            for pid in range(1, 30)])
    chain = graph.ancestors_of(29, max_depth=5)
    assert [node.pid for node in chain] == [29, 28, 27, 26, 25]

    looped = offline_graph(ProcessInfo(pid=11, name="a", ppid=12),
                           ProcessInfo(pid=12, name="b", ppid=11))
    assert [node.pid for node in looped.ancestors_of(11)] == [11, 12]


def test_graph_prunes_beyond_capacity():
    graph = ProcessGraph(live_lookup=lambda pid: None, max_nodes=3)
    graph.seed([ProcessInfo(pid=pid, name=f"p{pid}") for pid in range(1, 8)])
    assert len(graph._nodes) == 3  # oldest entries dropped