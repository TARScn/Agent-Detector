"""Agent Detector hook bridge: the process an Agent runs before a tool call.

The Agent spawns this script, it forwards the payload to the local decision
service, prints the answer and exits 0. It is deliberately tiny — stdlib only,
no FastAPI, no database, no rule engine — because it sits inside the Agent's
tool-call path and every import is latency the user feels (design §9.2, §11.4).

Usage (written into the Agent's hook config by ``agent-detector hooks install``)::

    python -m hook_bridge.entry --agent claude_code

Failure handling: if the decision service cannot be reached, the configured
failure mode decides. ``block`` (default) answers with the platform's "deny"
shape so a broken watchdog does not silently become no watchdog; ``allow`` is
audit mode and answers with the platform's "allow" shape. Both are marked in
the message so the reason is visible in the Agent's own transcript.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from hook_bridge.transport import DEFAULT_URL, TransportError, post_decision, read_token

# Platform response shapes for the failure path. The service owns the real
# mapping (hooks/adapters); this table exists only so the bridge can answer
# when the service is down, and must stay in sync with the adapters.
_FAILURE_RESPONSE = {
    "claude_code": lambda decision, reason: {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny" if decision == "block" else "allow",
        "permissionDecisionReason": f"[Agent Detector] {reason}"}},
    "codex_cli": lambda decision, reason: {
        "decision": "deny" if decision == "block" else "allow",
        "reason": f"[Agent Detector] {reason}"},
    "cursor": lambda decision, reason: {
        "permission": "deny" if decision == "block" else "allow",
        "user_message": f"Agent Detector 决策服务不可用：{reason}",
        "agent_message": f"[Agent Detector] {reason}"},
}
_DEFAULT_RESPONSE = lambda decision, reason: {  # noqa: E731
    "permission": "deny" if decision == "block" else "allow", "reason": reason}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hook_bridge", add_help=True,
                                     description="Agent Detector hook bridge")
    parser.add_argument("--agent", default=None,
                        help="agent type (claude_code / codex_cli / cursor)")
    parser.add_argument("--url", default=os.getenv("AGENT_DETECTOR_HOOK_URL", DEFAULT_URL))
    parser.add_argument("--token", default=None, help="internal API token")
    parser.add_argument("--token-file", default=None)
    parser.add_argument("--timeout", type=float,
                        default=float(os.getenv("AGENT_DETECTOR_HOOK_TIMEOUT", "5")))
    parser.add_argument("--failure-mode",
                        choices=["block", "allow"],
                        default=os.getenv("AGENT_DETECTOR_HOOK_FAILURE_MODE", "block"))
    parser.add_argument("--dump-payload", action="store_true",
                        help="print the parsed payload to stderr (debugging)")
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if not sys.stdin.isatty() else ""
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        return _fail(args, f"hook 载荷不是合法 JSON: {exc}")
    if not isinstance(payload, dict):
        return _fail(args, "hook 载荷不是对象")
    if args.dump_payload:
        print(json.dumps(payload, ensure_ascii=False)[:2000], file=sys.stderr)

    token = read_token(args.token, args.token_file)
    if not token:
        return _fail(args, "未找到内部 API Token（请先启动 Agent Detector 服务）")
    try:
        result = post_decision(args.url, payload=payload, agent_type=args.agent,
                               token=token, timeout=args.timeout,
                               parent_pid=os.getppid())
    except TransportError as exc:
        return _fail(args, str(exc))
    response = result.get("response")
    if not isinstance(response, dict):
        response = {}
    print(json.dumps(response, ensure_ascii=False))
    return 0


def _fail(args, reason: str) -> int:
    """Answer in the platform's own shape when the decision cannot be obtained."""
    render = _FAILURE_RESPONSE.get(args.agent or "", _DEFAULT_RESPONSE)
    print(f"[agent-detector] {reason}", file=sys.stderr)
    print(json.dumps(render(args.failure_mode, reason), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())