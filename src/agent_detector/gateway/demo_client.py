"""Send four localhost requests through the gateway to produce demo events."""
from __future__ import annotations

import os
import sys

import httpx


def run_demo(origin: str, proxy: str) -> list[tuple[str, int]]:
    """Fire the demo requests; returns (label, status) pairs. Raises on failure."""
    # Explicit `proxy` overrides the usual localhost NO_PROXY bypass.
    queries = [
        ("LLM", "POST", "/v1/chat/completions",
         {"model": "test-small",
          "messages": [{"role": "user", "content": "hello (not saved)"}]}, {}),
        ("MCP", "POST", "/mcp",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
          "params": {"name": "search", "arguments": {"query": "private-query"},
                     "_meta": {"io.modelcontextprotocol/clientInfo":
                               {"name": "demo", "version": "0.1.0"}}}},
         {"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call",
          "Mcp-Name": "search"}),
        ("A2A JSON-RPC", "POST", "/rpc",
         {"jsonrpc": "2.0", "id": 2, "method": "SendMessage",
          "params": {"message": {"role": "user", "parts": [{"text": "hello"}]}}},
         {"A2A-Version": "1.0"}),
        ("A2A Agent Card", "GET", "/.well-known/agent-card.json", None, {}),
    ]
    results: list[tuple[str, int]] = []
    with httpx.Client(proxy=proxy, trust_env=False, timeout=12) as client:
        for name, method, path, payload, headers in queries:
            response = client.request(method, origin + path, json=payload, headers=headers)
            results.append((name, response.status_code))
            response.raise_for_status()
    return results


def main() -> int:
    origin = os.getenv("AGD_DEMO_UPSTREAM", "http://127.0.0.1:9100")
    proxy = os.getenv("AGD_PROXY", "http://127.0.0.1:8899")
    try:
        for name, status in run_demo(origin, proxy):
            print(f"{name:<16} HTTP {status}")
    except httpx.HTTPError as exc:
        print(f"demo failed: {exc}", file=sys.stderr)
        return 1
    print("Done. Events should appear in the web console monitor page.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
