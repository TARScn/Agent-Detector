"""CLI: scan / agents / events / collect / policy / hooks / serve.

Every command here shares the engine with the console (design section 1.3) — no
CLI-only behaviour. Commands never elevate privileges, and the hook installer
writes nothing unless ``--apply`` is given explicitly.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from sqlalchemy.orm import Session

from agent_detector import __version__
from agent_detector.core.config import DB_PATH
from agent_detector.discovery.scanner.scan import run_scan
from agent_detector.storage.database import make_engine
from agent_detector.storage import (AgentInventoryRepository, AlertRepository,
                                                 AssetRepository, BehaviorEventRepository)

EXIT_OK, EXIT_USAGE, EXIT_ERROR = 0, 2, 3


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-detector",
        description="本机 AI Agent 资产发现、行为监测与执行前拦截（V0.2）")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--db", type=Path, default=None,
                        help=f"SQLite 数据库路径（默认 {DB_PATH}）")
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="启动本地控制台与 Hook 决策服务")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)

    scan = commands.add_parser("scan", help="执行一次资产扫描")
    scan.add_argument("--active", action="store_true", help="同时探测本机 HTTP 监听端口")
    scan.add_argument("--no-docker", action="store_true",
                      help="跳过 Docker 容器发现（默认自动探测本机 daemon，只读 API）")
    scan.add_argument("--json", action="store_true", help="输出原始 JSON")

    assets = commands.add_parser("assets", help="组件资产（含 MCP / 模型服务）")
    assets.add_argument("--scan-id", type=int, default=None)

    agents = commands.add_parser("agents", help="Agent 资产、实例与会话")
    agents_commands = agents.add_subparsers(dest="agents_command", required=True)
    agents_commands.add_parser("list", help="列出 Agent 资产与保护状态")
    agent_show = agents_commands.add_parser("show", help="查看单个 Agent 详情")
    agent_show.add_argument("asset_id")

    events = commands.add_parser("events", help="查看行为事件")
    events.add_argument("--limit", type=int, default=40)
    events.add_argument("--source", default=None,
                        help="native_hook | sysmon | auditd | poll | netmon")
    events.add_argument("--agent", default=None, help="按 Agent 名称过滤")
    events.add_argument("--event-type", default=None, help="如 proc.exec / tool_call")
    events.add_argument("--risk", default=None, help="low | medium | high | critical")
    events.add_argument("--json", action="store_true")

    alerts = commands.add_parser("alerts", help="查看安全告警")
    alerts.add_argument("--limit", type=int, default=20)
    alerts.add_argument("--status", default=None, help="open | acknowledged | resolved")

    monitor = commands.add_parser(
        "monitor", help="观察本机进程的 LLM API 调用（零合作，连接级）")
    monitor.add_argument("--duration", type=float, default=60.0)
    monitor.add_argument("--interval", type=float, default=None)

    collect = commands.add_parser("collect", help="采集系统行为事实")
    collect.add_argument("--mode", choices=["sysmon", "auditd", "tetragon", "poll"],
                         default=None,
                         help="默认：Windows 有 Sysmon 用 sysmon，Linux 有 Tetragon "
                              "导出用 tetragon，其次 auditd，否则 poll")
    collect.add_argument("--log", type=Path, default=None,
                         help="日志路径（auditd 日志或 Tetragon JSON 导出文件）")
    collect.add_argument("--duration", type=float, default=60.0)
    collect.add_argument("--interval", type=float, default=None)
    collect.add_argument("--from-start", action="store_true", help="从日志开头开始处理")

    replay = commands.add_parser("replay", help="离线回放一份采集日志（任意平台）")
    replay.add_argument("log", type=Path)
    replay.add_argument("--format", choices=["auditd", "tetragon"], default="auditd",
                        help="日志格式：auditd 文本（默认）或 Tetragon JSON 行")
    replay.add_argument("--json", action="store_true")

    commands.add_parser("channels", help="查看各采集通道可用状态")

    audit_rules = commands.add_parser("audit-rules", help="打印 auditd 规则与安装命令")
    audit_rules.add_argument("--watch-dir", action="append", default=[])
    audit_rules.add_argument("--read-dir", action="append", default=[])
    audit_rules.add_argument("--uid-min", type=int, default=1000)
    audit_rules.add_argument("--no-net", action="store_true")
    audit_rules.add_argument("--kill", action="store_true")
    audit_rules.add_argument("--persistent", action="store_true")

    tetragon = commands.add_parser("tetragon", help="Tetragon 通道状态与部署命令")
    tetragon.add_argument("--log", type=Path, default=None,
                          help="JSON 导出文件路径（默认 /var/log/tetragon/events.json）")

    policy = commands.add_parser("policy", help="策略规则与决策自检")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_commands.add_parser("list", help="列出策略规则")
    policy_test = policy_commands.add_parser(
        "test", help="对一条工具调用做一次真实策略判断")
    policy_test.add_argument("--agent", default="claude_code")
    policy_test.add_argument("--tool", default="Bash")
    # dest is renamed: argparse would otherwise overwrite the top-level
    # `command` attribute that selects the subcommand.
    policy_test.add_argument("--command", dest="shell_command", default=None,
                             help="shell 命令")
    policy_test.add_argument("--path", default=None, help="文件路径（Write/Read 类工具）")
    policy_test.add_argument("--cwd", default=None)
    policy_test.add_argument("--json", action="store_true")

    hooks = commands.add_parser("hooks", help="Agent Hook 安装与状态")
    hook_commands = hooks.add_subparsers(dest="hooks_command", required=True)
    hook_commands.add_parser("status", help="列出各 Agent 的 Hook 配置状态")
    for name, help_text in (("plan", "预览将要写入的 Hook 配置（不写文件）"),
                            ("install", "把 Hook 写入 Agent 配置（默认 dry-run）"),
                            ("uninstall", "移除本工具写入的 Hook 条目")):
        hook_command = hook_commands.add_parser(name, help=help_text)
        hook_command.add_argument("agent", nargs="?", default=None,
                                  help="claude_code | codex_cli | cursor（省略则全部）")
        hook_command.add_argument("--apply", action="store_true",
                                  help="真正写文件（会先备份原配置）")
    snippet = hook_commands.add_parser("snippet", help="打印可手工粘贴的配置片段")
    snippet.add_argument("agent")

    purge = commands.add_parser("purge", help="按保留策略清理行为事件")
    purge.add_argument("--older-than-days", type=int, default=None)
    purge.add_argument("--source", default=None)
    purge.add_argument("--all", action="store_true", help="删除该来源的全部事件（破坏性）")

    args = parser.parse_args(argv)
    engine = make_engine(args.db or DB_PATH)
    handlers = {
        "serve": _serve, "scan": _scan, "assets": _assets, "agents": _agents,
        "events": _events, "alerts": _alerts, "monitor": _monitor, "collect": _collect,
        "replay": _replay, "channels": _channels, "audit-rules": _audit_rules,
        "tetragon": _tetragon,
        "policy": _policy, "hooks": _hooks, "purge": _purge,
    }
    return handlers[args.command](args, engine)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def _serve(args, engine) -> int:
    from agent_detector.core.config import WEB_HOST, WEB_PORT

    host = args.host or WEB_HOST
    port = args.port or WEB_PORT
    try:
        import uvicorn
    except ImportError:
        print('需要 uvicorn：pip install -e ".[test]"', file=sys.stderr)
        return EXIT_ERROR
    print(f"Agent Detector 控制台： http://{host}:{port}  （Ctrl+C 退出）")
    print("Hook 决策接口：/internal/v1/hooks/decide（仅监听 loopback，需 Token）")
    from agent_detector.console.api.app import create_app

    uvicorn.run(create_app(), host=host, port=port, log_level="info")
    return EXIT_OK


def _scan(args, engine) -> int:
    result = run_scan(engine, active=args.active, docker_enabled=not args.no_docker)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return EXIT_OK
    observations = result["observations"]
    print(f"scan #{result['scan_id']} {result['mode']} {result['status']}: "
          f"{observations['processes']} processes, "
          f"{observations['listening_sockets']} listening sockets")
    docker_stats = result.get("docker") or {}
    print(f"  docker: {docker_stats.get('containers_total', 0)} containers, "
          f"{docker_stats.get('candidates', 0)} candidates, "
          f"{docker_stats.get('agents', 0)} agents"
          + (f" ({docker_stats.get('error')})" if docker_stats.get("error") else ""))
    for agent in result.get("agent_assets", []):
        print(f"  [Agent] {agent['name']:<16} {agent['agent_type']:<14} "
              f"protection={agent['protection_status']:<13} "
              f"hook={agent['hook_state']:<13} instances={agent['instance_count']}")
    for asset in result.get("asset_summaries", []):
        _print_asset_row(asset, indent="  ")
    for error in result.get("errors", []):
        print(f"  error: {error['detector']}: {error['error']}", file=sys.stderr)
    return EXIT_OK


def _assets(args, engine) -> int:
    with Session(engine) as session:
        repository = AssetRepository(session)
        rows = (repository.list_snapshots(args.scan_id) if args.scan_id
                else repository.latest_snapshots())
    if not rows:
        print("no assets recorded; run `agent-detector scan` first")
        return EXIT_OK
    for asset in rows:
        _print_asset_row(asset)
    return EXIT_OK


def _agents(args, engine) -> int:
    with Session(engine) as session:
        repository = AgentInventoryRepository(session)
        if args.agents_command == "list":
            instances = repository.list_instances()
            counts: dict[str, int] = {}
            for instance in instances:
                counts[instance["asset_id"]] = counts.get(instance["asset_id"], 0) + 1
            from agent_detector.console.api.agent_view import (app_name_map,
                                                               merge_agent_rows)
            assets = merge_agent_rows(repository.list_assets(),
                                      app_name_map(session), counts)
            if not assets:
                print("尚未建立 Agent 清单；先运行 `agent-detector scan`")
                return EXIT_OK
            for asset in assets:
                container = (asset.get("container_id") or "")[:12]
                print(f"{asset['name']:<16} {asset['agent_type']:<14} "
                      f"version={asset['version']:<12} "
                      f"protection={asset['protection_status']:<13} "
                      f"hook={asset['hook_state']:<13} "
                      f"instances={counts.get(asset['asset_id'], 0):<2} "
                      f"mcp={len(asset['mcp_servers'])}"
                      + (f" container={container}" if container else ""))
                for dependency in asset.get("dependencies", []):
                    print(f"    依赖: {dependency['name']} {dependency['version']}"
                          f"（{dependency['asset_type']}）")
                for note in asset["notes"]:
                    print(f"    note: {note}")
            return EXIT_OK
        detail = repository.get_asset(args.asset_id)
        if detail is None:
            print(f"未找到 Agent 资产 {args.asset_id}", file=sys.stderr)
            return EXIT_ERROR
        print(json.dumps({**detail,
                          "instances": repository.list_instances(args.asset_id, True),
                          "sessions": repository.list_sessions(asset_id=args.asset_id)},
                         ensure_ascii=False, indent=2))
        return EXIT_OK


def _events(args, engine) -> int:
    with Session(engine) as session:
        events = BehaviorEventRepository(session).list_events(
            limit=args.limit, source=args.source, agent_label=args.agent,
            event_type=args.event_type, risk_level=args.risk)
    if args.json:
        print(json.dumps({"items": events}, ensure_ascii=False, indent=2))
        return EXIT_OK
    if not events:
        print("no behavior events on record")
        return EXIT_OK
    for event in events:
        target = event["target"] or event["endpoint"] or "-"
        decision = event["decision"] or "-"
        risk = event["risk_level"] or "-"
        print(f"{event['observed_at']} {event['source']:<11} "
              f"{event['agent_label']:<16} {event['operation']:<18} "
              f"{event['event_type']:<12} risk={risk:<9} decision={decision:<6} "
              f"pid={event['pid'] or '-'} {target[:70]}")
    return EXIT_OK


def _alerts(args, engine) -> int:
    with Session(engine) as session:
        repository = AlertRepository(session)
        items = repository.list_alerts(limit=args.limit, status=args.status)
        stats = repository.stats()
    print(f"alerts: total={stats['alert_count']} open_high={stats['open_high']} "
          f"by_risk={stats['by_risk']}")
    for alert in items:
        print(f"  #{alert['id']} {alert['created_at']} [{alert['risk_level']:<8}] "
              f"{alert['decision']:<6} {alert['status']:<12} "
              f"{alert['agent_label']:<16} {alert['title'][:50]}")
    return EXIT_OK


def _monitor(args, engine) -> int:
    from agent_detector.monitoring.services.monitor import MonitorManager

    manager = MonitorManager(engine, interval=args.interval)
    duration = max(1.0, args.duration)
    print(f"observing outbound connections for {duration:.0f}s "
          f"(interval {manager.interval}s)...")
    deadline = time.monotonic() + duration
    total = 0
    try:
        while time.monotonic() < deadline:
            for observation in manager.run_once():
                total += 1
                who = observation.process_name or f"pid-{observation.pid}"
                print(f"  {who} -> {observation.host} [{observation.match_kind}]")
            time.sleep(manager.interval)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
    finally:
        manager.close()
    with Session(engine) as session:
        stats = BehaviorEventRepository(session).stats(source="netmon")
    print(f"done: {total} event(s) this window, "
          f"{stats['event_count']} netmon events on record")
    return EXIT_OK


def _collect(args, engine) -> int:
    from agent_detector.monitoring.services.ingest import BehaviorIngestError, BehaviorIngestService

    try:
        service = BehaviorIngestService(engine, mode=args.mode, log_path=args.log,
                                        interval=args.interval,
                                        from_start=args.from_start)
    except BehaviorIngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    duration = max(1.0, args.duration)
    print(f"collecting system behavior for {duration:.0f}s "
          f"(mode {service.mode}, source {service.source}, interval {service.interval}s)...")
    deadline = time.monotonic() + duration
    total = 0
    try:
        while time.monotonic() < deadline:
            for item in service.run_once():
                total += 1
                print(f"  {item['agent_label']} -> {item['operation']} "
                      f"{item['target'] or ''} [pid {item['pid']}] risk={item['risk_level']}")
            time.sleep(service.interval if service.mode == "poll" else 0.5)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
    except BehaviorIngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        service.close()
    with Session(engine) as session:
        stats = BehaviorEventRepository(session).stats()
    print(f"done: {total} event(s) this window, "
          f"{stats['event_count']} behavior events on record")
    return EXIT_OK


def _replay(args, engine) -> int:
    from agent_detector.monitoring.services.ingest import BehaviorIngestService

    result = BehaviorIngestService(engine, mode="replay").run_replay(
        args.log, format=args.format)
    if args.json:
        print(json.dumps({key: value for key, value in result.items() if key != "items"},
                         ensure_ascii=False, indent=2))
        return EXIT_OK
    print(f"replayed {result['log_path']} ({result['format']}): "
          f"{result['facts']} fact(s), {result['events']} event(s) stored")
    for item in result["items"]:
        print(f"  {item['agent_label']} -> {item['operation']} "
              f"{item['target'] or ''} [pid {item['pid']}] risk={item['risk_level']}")
    return EXIT_OK


def _channels(args, engine) -> int:
    import platform

    from agent_detector.monitoring.collectors.host.sysmon import sysmon_available
    from agent_detector.monitoring.collectors.ebpf.tetragon import tetragon_available
    from agent_detector.core.config import SYSMON_CHANNEL

    print(f"platform: {platform.system()} {platform.release()}")
    sysmon = sysmon_available(SYSMON_CHANNEL)
    print(f"sysmon  : {'available' if sysmon.available else 'unavailable'} "
          f"({sysmon.reason or sysmon.channel})")
    print(f"auditd  : {'available (Linux)' if platform.system() == 'Linux' else 'unavailable'}")
    tetra = tetragon_available()
    print(f"tetragon: {'available' if tetra.available else 'unavailable'} "
          f"({tetra.reason or tetra.log_path})")
    print("poll    : available (无需权限，仅进程执行级)")
    print("netmon  : available (只读 socket 表与 DNS 缓存)")
    print("hook    : 需要为每个 Agent 安装 Hook，见 hooks status")
    return EXIT_OK


def _tetragon(args, engine) -> int:
    from agent_detector.core.config import TETRA_LOG
    from agent_detector.monitoring.collectors.ebpf.tetragon import (install_commands,
                                                                    tetragon_available,
                                                                    uninstall_commands)

    log_path = str(args.log) if args.log else TETRA_LOG
    status = tetragon_available(log_path)
    if status.available:
        print(f"tetragon: available ({log_path})")
    else:
        print(f"tetragon: unavailable — {status.reason}")
    print("\n# 部署（systemd 单机方式；本工具只打印，不提权）")
    for command in install_commands(log_path):
        print(command)
    print("\n# 卸载")
    for command in uninstall_commands():
        print(command)
    return EXIT_OK


def _audit_rules(args, engine) -> int:
    from agent_detector.monitoring.collectors.audit.rules_template import (build_rules, install_commands,
                                                               uninstall_commands)

    try:
        rule_set = build_rules(args.watch_dir, uid_min=args.uid_min,
                               include_net=not args.no_net, include_kill=args.kill,
                               read_dirs=args.read_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print("# install (run as root; this tool never elevates privileges itself)")
    for command in install_commands(rule_set, persistent=args.persistent):
        print(command)
    print("\n# uninstall")
    for command in uninstall_commands(rule_set, persistent=args.persistent):
        print(command)
    if not args.watch_dir:
        print("\nnote: no --watch-dir given, so file operations are not audited",
              file=sys.stderr)
    return EXIT_OK


def _policy(args, engine) -> int:
    from agent_detector.core.enums import HookEvent
    from agent_detector.core.models import ToolCall
    from agent_detector.interception.policy.engine import PolicyEngine
    from agent_detector.interception.policy.loader import load_policies
    from agent_detector.storage import PolicyRepository

    loaded = load_policies()
    for error in loaded.errors:
        print(f"policy load error: {error['file']}: {error['error']}", file=sys.stderr)
    if args.policy_command == "list":
        with Session(engine) as session:
            repository = PolicyRepository(session)
            repository.sync_from_ruleset(loaded.ruleset)
            overrides = repository.overrides()
            session.commit()
        engine_ = PolicyEngine(loaded.ruleset, overrides=overrides)
        for rule in engine_.rules():
            enabled = "on " if engine_.rule_enabled(rule) else "off"
            print(f"[{enabled}] p{rule.priority:<4} {rule.id:<34} "
                  f"{engine_.rule_decision(rule).value:<6} risk={rule.risk.value:<9} "
                  f"{rule.name}")
        return EXIT_OK
    tool_input: dict = {}
    if args.shell_command:
        tool_input["command"] = args.shell_command
    if args.path:
        tool_input["file_path"] = args.path
    call = ToolCall(agent_type=args.agent, event_type=HookEvent.PRE_TOOL_USE,
                    tool_name=args.tool, tool_input=tool_input, cwd=args.cwd)
    verdict = PolicyEngine(loaded.ruleset).decide(call)
    if args.json:
        print(json.dumps({"decision": verdict.decision.value, "risk": verdict.risk.value,
                          "reason": verdict.reason,
                          "matched_rules": list(verdict.matched_rules),
                          "policy_id": verdict.policy_id}, ensure_ascii=False, indent=2))
        return EXIT_OK
    print(f"decision={verdict.decision.value} risk={verdict.risk.value} "
          f"policy={verdict.policy_id or '-'}")
    print(f"reason: {verdict.reason}")
    if verdict.matched_rules:
        print(f"matched: {', '.join(verdict.matched_rules)}")
    return EXIT_OK


def _hooks(args, engine) -> int:
    from agent_detector.interception.hooks.installer import (config_snippet, inspect_all, install, plan,
                                               uninstall)
    from agent_detector.interception.hooks.registry import ADAPTERS

    command = args.hooks_command
    if command == "status":
        for item in inspect_all():
            print(f"{item['display_name']:<14} {item['state']:<14} "
                  f"entries={item['entries']:<2} {item['config_path']}")
            for note in list(item["notes"]) + list(item.get("spec_notes") or []):
                print(f"    note: {note}")
        return EXIT_OK
    if command == "snippet":
        snippet = config_snippet(args.agent)
        print(f"# {snippet['config_path']}")
        print(json.dumps(snippet["events"], ensure_ascii=False, indent=2))
        return EXIT_OK
    targets = [args.agent] if args.agent else list(ADAPTERS)
    for target in targets:
        try:
            if command == "plan":
                result = plan(target)
            elif command == "install":
                result = install(target, apply=args.apply)
            else:
                result = uninstall(target, apply=args.apply)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if command == "uninstall":
            print(f"{target}: uninstall removed={result['removed']} "
                  f"written={result['written']} ({result['config_path']})")
        else:
            print(f"{target}: {command} changed={result['changed']} "
                  f"written={result['written']} ({result['config_path']})")
        if result.get("backup"):
            print(f"    backup: {result['backup']}")
        if not result["written"]:
            print("    （dry-run：未写入任何文件；加 --apply 才会修改配置并备份）")
    return EXIT_OK


def _purge(args, engine) -> int:
    from agent_detector.core.config import BEHAVIOR_RETENTION_DAYS
    from agent_detector.monitoring.services.retention import (clear_behavior_events,
                                                   purge_behavior_events)

    if args.all:
        removed = clear_behavior_events(engine, source=args.source)
        print(f"deleted {removed} behavior event(s) ({args.source or 'all sources'})")
        return EXIT_OK
    days = BEHAVIOR_RETENTION_DAYS if args.older_than_days is None else args.older_than_days
    if days <= 0:
        print("retention disabled (0 days); nothing purged")
        return EXIT_OK
    removed = purge_behavior_events(engine, days, source=args.source)
    print(f"purged {removed} behavior event(s) older than {days} day(s)")
    return EXIT_OK


def _print_asset_row(asset: dict, indent: str = "") -> None:
    states = ",".join(asset["states"]) or "UNKNOWN"
    version = asset["version"]
    source = f" ({asset['version_source']})" if version != "UNKNOWN" else ""
    print(f"{indent}{asset['name']:<24} {asset['asset_type']:<16} [{states}] "
          f"version={version}{source} confidence={asset['confidence']:.2f}")


if __name__ == "__main__":
    sys.exit(main())