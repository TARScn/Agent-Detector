"""CLI entry point: agent-detector scan / assets / monitor (plan section 11.2)."""
import argparse
import json
import sys
from pathlib import Path

from sqlalchemy.orm import Session

from agent_detector.application.scan_service import run_scan
from agent_detector.common.config import DB_PATH
from agent_detector.persistence.database import make_engine
from agent_detector.persistence.repositories import AssetRepository


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
    return 2


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
