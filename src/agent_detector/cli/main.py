"""CLI entry point: agent-detector scan / assets / monitor / behavior (plan section 11.2)."""
import argparse
import json
import sys
import time
from pathlib import Path

from sqlalchemy.orm import Session

from agent_detector.application.scan_service import run_scan
from agent_detector.common.config import DB_PATH
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.repositories import (AssetRepository,
                                                     BehaviorEventRepository)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agent-detector",
                                     description="Local AI agent asset detector")
    parser.add_argument("--db", type=Path, default=None,
                        help=f"SQLite database path (default: {DB_PATH})")
    commands = parser.add_subparsers(dest="command", required=True)

    scan_parser = commands.add_parser("scan", help="run a detection scan")
    scan_parser.add_argument("--active", action="store_true",
                             help="also probe local HTTP listeners")
    scan_parser.add_argument("--json", action="store_true", help="print raw JSON result")

    assets_parser = commands.add_parser("assets", help="asset commands")
    assets_commands = assets_parser.add_subparsers(dest="assets_command", required=True)
    assets_commands.add_parser("list", help="list known assets with latest snapshots")

    monitor_parser = commands.add_parser(
        "monitor", help="observe LLM API calls of local processes for a time window")
    monitor_parser.add_argument("--duration", type=float, default=60.0,
                                help="observation window in seconds (default: 60)")
    monitor_parser.add_argument("--interval", type=float, default=None,
                                help="poll interval in seconds (default from config)")

    behavior_parser = commands.add_parser(
        "behavior", help="system behavior monitoring (auditd / poll / replay)")
    behavior_commands = behavior_parser.add_subparsers(dest="behavior_command", required=True)

    behavior_commands.add_parser("status", help="show behavior ingest status")

    rules_parser = behavior_commands.add_parser(
        "rules", help="print the auditd rules and their install/uninstall commands")
    rules_parser.add_argument("--watch-dir", action="append", default=[],
                              help="directory watched for file operations (repeatable)")
    rules_parser.add_argument("--read-dir", action="append", default=[],
                              help="directory whose reads are audited (noisy, opt-in)")
    rules_parser.add_argument("--uid-min", type=int, default=1000,
                              help="minimum uid for exec/network rules (default: 1000)")
    rules_parser.add_argument("--no-net", action="store_true",
                              help="omit the connect rule")
    rules_parser.add_argument("--kill", action="store_true",
                              help="include the kill rule (noisy)")
    rules_parser.add_argument("--persistent", action="store_true",
                              help="also print rules.d + augenrules commands")

    events_parser = behavior_commands.add_parser("events", help="list stored behavior events")
    events_parser.add_argument("--limit", type=int, default=50)
    events_parser.add_argument("--agent", default=None, help="filter by agent label")
    events_parser.add_argument("--source", default=None, help="auditd | poll | netmon")
    events_parser.add_argument("--event-type", default=None, help="e.g. proc.exec")

    collect_parser = behavior_commands.add_parser(
        "collect", help="collect system behavior for a time window")
    collect_parser.add_argument("--mode", choices=["auditd", "poll"], default=None,
                                help="auditd log tail or unprivileged process sampling")
    collect_parser.add_argument("--log", type=Path, default=None,
                                help="audit log path (auditd mode)")
    collect_parser.add_argument("--duration", type=float, default=60.0)
    collect_parser.add_argument("--interval", type=float, default=None)
    collect_parser.add_argument("--from-start", action="store_true",
                                help="process the existing log from its beginning")

    replay_parser = behavior_commands.add_parser(
        "replay", help="process a saved audit log offline (works on any platform)")
    replay_parser.add_argument("log", type=Path)
    replay_parser.add_argument("--json", action="store_true")

    purge_parser = behavior_commands.add_parser("purge", help="apply the retention window")
    purge_parser.add_argument("--older-than-days", type=int, default=None,
                              help="retention window (default from config)")
    purge_parser.add_argument("--source", default=None,
                              help="limit to one source (auditd | poll | netmon)")
    purge_parser.add_argument("--all", action="store_true",
                              help="delete ALL events for --source (or every source) — destructive")

    args = parser.parse_args(argv)
    engine = make_engine(args.db or DB_PATH)

    if args.command == "scan":
        result = run_scan(engine, active=args.active)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            _print_scan(result)
        return 0
    if args.command == "assets" and args.assets_command == "list":
        with Session(engine) as session:
            for asset in AssetRepository(session).latest_snapshots():
                _print_asset_row(asset)
        return 0
    if args.command == "monitor":
        return _monitor_command(args, engine)
    if args.command == "behavior":
        return _behavior_command(args, engine)
    return 2


def _monitor_command(args, engine) -> int:
    from agent_detector.behavior.monitor_service import MonitorManager
    from agent_detector.persistence.repositories import BehaviorEventRepository

    manager = MonitorManager(engine, interval=args.interval)
    duration = max(1.0, args.duration)
    print(f"observing outbound connections for {duration:.0f}s "
          f"(interval {manager.interval}s)...")
    deadline = time.monotonic() + duration
    total = 0
    try:
        while time.monotonic() < deadline:
            for obs in manager.run_once():
                total += 1
                who = obs.process_name or f"pid-{obs.pid}"
                print(f"  {who} -> {obs.host} [{obs.match_kind}]")
            time.sleep(manager.interval)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
    finally:
        manager.close()
    with Session(engine) as session:
        stats = BehaviorEventRepository(session).stats(source="netmon")
    print(f"done: {total} event(s) this window, "
          f"{stats['event_count']} netmon events on record")
    return 0


def _behavior_command(args, engine) -> int:
    handlers = {
        "status": _behavior_status,
        "rules": _behavior_rules,
        "events": _behavior_events,
        "collect": _behavior_collect,
        "replay": _behavior_replay,
        "purge": _behavior_purge,
    }
    handler = handlers.get(args.behavior_command)
    return handler(args, engine) if handler else 2


def _behavior_status(args, engine) -> int:
    from agent_detector.behavior.ingest_service import BehaviorIngestService

    status = BehaviorIngestService(engine).status()
    print(f"mode={status['mode']} running={status['running']} "
          f"log={status['log_path'] or '-'} readable={status['log_readable']}")
    print(f"rules={status['rule_count']} keys={len(status['keys'])} "
          f"suppress={status['suppress_seconds']}s retention={status['retention_days']}d "
          f"path_policy={status['path_policy']} store_argv={status['store_argv']}")
    print(f"batches={status['batches']} records={status['records_read']} "
          f"facts={status['facts']} events={status['events']} "
          f"suppressed={status['suppressed']}")
    print(f"dropped: no_rule={status['dropped_no_rule']} "
          f"unattributed={status['dropped_unattributed']} rate={status['dropped_rate']}")
    for error in status["rules_errors"]:
        print(f"rule error: {error['file']}: {error['error']}", file=sys.stderr)
    return 0


def _behavior_rules(args, engine) -> int:
    from agent_detector.behavior.audit.rules_template import (build_rules, install_commands,
                                                              uninstall_commands)

    try:
        rule_set = build_rules(args.watch_dir, uid_min=args.uid_min,
                               include_net=not args.no_net, include_kill=args.kill,
                               read_dirs=args.read_dir)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("# install (run as root; this tool never elevates privileges itself)")
    for command in install_commands(rule_set, persistent=args.persistent):
        print(command)
    print()
    print("# uninstall")
    for command in uninstall_commands(rule_set, persistent=args.persistent):
        print(command)
    if not args.watch_dir:
        print()
        print("note: no --watch-dir given, so file operations are not audited",
              file=sys.stderr)
    return 0


def _behavior_events(args, engine) -> int:
    with Session(engine) as session:
        events = BehaviorEventRepository(session).list_events(
            limit=args.limit, source=args.source, agent_label=args.agent,
            event_type=args.event_type)
    if not events:
        print("no behavior events on record")
        return 0
    for event in events:
        target = event["target"] or event["endpoint"] or "-"
        print(f"{event['observed_at']} {event['source']:<7} "
              f"{event['agent_label']:<18} {event['operation']:<18} "
              f"{event['event_type']:<12} pid={event['pid'] or '-'} {target}")
    return 0


def _behavior_collect(args, engine) -> int:
    from agent_detector.behavior.ingest_service import (BehaviorIngestError,
                                                        BehaviorIngestService)

    try:
        service = BehaviorIngestService(engine, mode=args.mode, log_path=args.log,
                                        interval=args.interval,
                                        from_start=args.from_start)
    except BehaviorIngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    duration = max(1.0, args.duration)
    print(f"collecting system behavior for {duration:.0f}s "
          f"(mode {service.mode}, interval {service.interval}s)...")
    deadline = time.monotonic() + duration
    total = 0
    try:
        while time.monotonic() < deadline:
            for item in service.run_once():
                total += 1
                print(f"  {item['agent_label']} -> {item['operation']} "
                      f"{item['target'] or ''} [pid {item['pid']}]")
            time.sleep(service.interval)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
    except BehaviorIngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        service.close()
    with Session(engine) as session:
        stats = BehaviorEventRepository(session).stats()
    print(f"done: {total} event(s) this window, "
          f"{stats['event_count']} behavior events on record")
    return 0


def _behavior_replay(args, engine) -> int:
    from agent_detector.behavior.ingest_service import BehaviorIngestService

    result = BehaviorIngestService(engine, mode="replay").run_replay(args.log)
    if args.json:
        print(json.dumps({k: v for k, v in result.items() if k != "items"},
                         ensure_ascii=False, indent=2))
        return 0
    print(f"replayed {result['log_path']}: {result['facts']} fact(s), "
          f"{result['events']} event(s) stored")
    for item in result["items"]:
        print(f"  {item['agent_label']} -> {item['operation']} "
              f"{item['target'] or ''} [pid {item['pid']}]")
    return 0


def _behavior_purge(args, engine) -> int:
    from agent_detector.behavior.maintenance import (clear_behavior_events,
                                                     purge_behavior_events)
    from agent_detector.common.config import BEHAVIOR_RETENTION_DAYS

    if args.all:
        removed = clear_behavior_events(engine, source=args.source)
        scope = args.source or "all sources"
        print(f"deleted {removed} behavior event(s) ({scope})")
        return 0
    days = BEHAVIOR_RETENTION_DAYS if args.older_than_days is None else args.older_than_days
    if days <= 0:
        print("retention disabled (0 days); nothing purged")
        return 0
    removed = purge_behavior_events(engine, days, source=args.source)
    print(f"purged {removed} behavior event(s) older than {days} day(s)")
    return 0


def _print_scan(result: dict) -> None:
    observations = result["observations"]
    print(f"scan #{result['scan_id']} {result['mode']} {result['status']}: "
          f"{observations['processes']} processes, "
          f"{observations['listening_sockets']} listening sockets")
    for asset in result.get("asset_summaries", []):
        _print_asset_row(asset, indent="  ")
    for error in result.get("errors", []):
        print(f"  detector error: {error['detector']}: {error['error']}", file=sys.stderr)


def _print_asset_row(asset: dict, indent: str = "") -> None:
    states = ",".join(asset["states"]) or "UNKNOWN"
    version = asset["version"]
    source = f" ({asset['version_source']})" if version != "UNKNOWN" else ""
    print(f"{indent}{asset['name']:<24} {asset['asset_type']:<16} [{states}] "
          f"version={version}{source} confidence={asset['confidence']:.2f}")


if __name__ == "__main__":
    sys.exit(main())
