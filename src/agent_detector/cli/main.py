"""CLI entry point: agent-detector scan / assets / gateway (plan section 11.2)."""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from agent_detector.application.scan_service import run_scan
from agent_detector.common.config import DB_PATH
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.repositories import AssetRepository

DEMO_UPSTREAM_PORT = 9100


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

    gateway_parser = commands.add_parser("gateway",
                                         help="local gateway control (traffic monitoring)")
    gateway_commands = gateway_parser.add_subparsers(dest="gateway_command", required=True)
    gateway_commands.add_parser("start", help="start the gateway proxy on 127.0.0.1")
    gateway_commands.add_parser("stop", help="stop the gateway")
    gateway_commands.add_parser("status", help="show gateway status")
    gateway_commands.add_parser("demo",
                                help="send demo LLM/MCP/A2A traffic through the gateway")

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
    if args.command == "gateway":
        return _gateway_command(args, engine)
    return 2


def _gateway_command(args, engine) -> int:
    from agent_detector.gateway.manager import GatewayError, GatewayManager

    manager = GatewayManager(db_path=args.db or DB_PATH)
    try:
        if args.gateway_command == "start":
            status = manager.start()
            print(f"gateway running on {status['listen']} (pid {status['pid']}, "
                  f"label {status['agent_label']})")
            return 0
        if args.gateway_command == "stop":
            manager.stop()
            print("gateway stopped")
            return 0
        if args.gateway_command == "status":
            status = manager.status()
            state = "running" if status["running"] else "stopped"
            print(f"gateway {state}: listen={status['listen']} "
                  f"mitmdump_available={status['available']} label={status['agent_label']} "
                  f"hosts={','.join(status['observed_hosts'])}")
            return 0
        if args.gateway_command == "demo":
            return _gateway_demo(manager, engine)
    except GatewayError as exc:
        print(f"gateway error: {exc}", file=sys.stderr)
        return 1
    return 2


def _gateway_demo(manager, engine) -> int:
    from agent_detector.gateway.demo_client import run_demo
    from agent_detector.persistence.repositories import BehaviorEventRepository

    status = manager.status()
    if not status["running"]:
        print("gateway is not running; start it first with 'agent-detector gateway start' "
              "or the monitor page in the web console", file=sys.stderr)
        return 1

    upstream = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "agent_detector.gateway.mock_upstream:app",
         "--host", "127.0.0.1", "--port", str(DEMO_UPSTREAM_PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    origin = f"http://127.0.0.1:{DEMO_UPSTREAM_PORT}"
    try:
        _wait_for_upstream(origin)
        results = run_demo(origin, f"http://127.0.0.1:{status['port']}")
        for name, code in results:
            print(f"{name:<16} HTTP {code}")
        with Session(engine) as session:
            stats = BehaviorEventRepository(session).stats()
        print(f"Done. {stats['event_count']} behavior events recorded "
              f"({', '.join(f'{k}={v}' for k, v in sorted(stats['by_protocol'].items()))}). "
              f"See the monitor page in the web console.")
        return 0
    except (httpx.HTTPError, RuntimeError) as exc:
        print(f"demo failed: {exc}", file=sys.stderr)
        return 1
    finally:
        upstream.terminate()


def _wait_for_upstream(origin: str, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with httpx.Client(trust_env=False, timeout=2) as client:
                if client.get(origin + "/.well-known/agent-card.json").status_code == 200:
                    return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise RuntimeError(f"mock upstream did not become ready on {origin}")


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
