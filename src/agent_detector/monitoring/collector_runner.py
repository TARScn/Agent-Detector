"""Detached collector child: the ingest pipeline in its own process.

``python -m agent_detector.monitoring.collector_runner`` is what
:class:`~agent_detector.monitoring.services.collector_process.CollectorProcessManager`
spawns. Motivation: the pipeline (Sysmon XML render/parse, rule matching,
attribution) is CPU-bound Python; run inside the console process it shares
the GIL with the API and stalls the console under real event volume. The
child runs the exact :class:`BehaviorIngestService` pipeline inline — no
worker thread needed, this process exists for the pipeline — and publishes
the collector-status file so the console shows real counters either way.

Parent-death watchdog: stdin is a pipe the parent keeps open; when the
parent dies (or closes it deliberately as the graceful stop signal), the
read returns EOF and the runner shuts the pipeline down cleanly, publishing
a stopped status. Start failures (unavailable channel) publish the reason
in ``last_error`` and exit 3.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent_detector.monitoring.collector_runner",
        description="运行系统行为采集子进程（由控制台进程管理）")
    parser.add_argument("--mode", default=None,
                        help="sysmon | auditd | tetragon | poll（缺省按平台选择）")
    parser.add_argument("--log", default=None, help="tail 通道的日志文件路径")
    parser.add_argument("--from-start", action="store_true",
                        help="从日志最旧一条开始而不是只看新增")
    parser.add_argument("--interval", type=float, default=None,
                        help="poll 模式采样间隔（秒）")
    return parser


def main(argv: list[str] | None = None) -> int:
    from agent_detector.core.config import COLLECTOR_STATUS_PATH
    from agent_detector.monitoring.services.collector_status import write_collector_status
    from agent_detector.monitoring.services.ingest import (BehaviorIngestError,
                                                           BehaviorIngestService)
    from agent_detector.storage.database import make_engine
    from agent_detector.core.config import DB_PATH

    args = _build_parser().parse_args(argv)
    engine = make_engine(DB_PATH)
    try:
        service = BehaviorIngestService(engine, mode=args.mode, log_path=args.log,
                                        interval=args.interval,
                                        from_start=args.from_start)
    except BehaviorIngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    service.collector_pid = None
    stop = threading.Event()
    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, lambda *_: stop.set())
            except (OSError, ValueError):  # pragma: no cover - platform edge
                pass

    def _watch_parent() -> None:
        """EOF on stdin means the managing console is gone: stop cleanly."""
        try:
            while sys.stdin.buffer.read(4096):
                pass
        except Exception:  # pragma: no cover - closed/crazy stdin
            pass
        stop.set()

    try:
        service._ensure_ready()
    except BehaviorIngestError as exc:
        service.last_error = str(exc)
        write_collector_status(service.status(), path=COLLECTOR_STATUS_PATH)
        print(f"error: {exc}", file=sys.stderr)
        return 3

    service.collector_pid = os.getpid()
    service.inline_loop = True
    watcher = threading.Thread(target=_watch_parent, name="collector-parent-watch",
                               daemon=True)
    watcher.start()
    write_collector_status(service.status(), path=COLLECTOR_STATUS_PATH)
    print(f"collector running (pid {service.collector_pid}, mode {service.mode})",
          flush=True)
    try:
        while not stop.is_set():
            began = time.monotonic()
            try:
                service.run_once()
            except Exception:  # one bad batch must not kill the collector
                service.last_error = "batch failed (see collector.log)"
            wait = (max(0.2, service.interval - (time.monotonic() - began))
                    if service.mode == "poll" else 0.5)
            stop.wait(wait)
        return 0
    finally:
        # The status file must stop advertising a live collector the moment
        # this process leaves — no sixty-second aging delay.
        service.inline_loop = False
        write_collector_status(service.status(), path=COLLECTOR_STATUS_PATH)
        engine.dispose()


if __name__ == "__main__":
    sys.exit(main())
