"""Local explicit-proxy gateway (Agent Gateway Manager, G1).

An optional mitmproxy-based observer: agents that are explicitly pointed at the
gateway (per-process HTTP(S)_PROXY or SDK proxy setting) have their LLM / MCP /
A2A protocol calls classified into bounded metadata events and persisted to the
behavior_events table. Protocol events prove a call happened; they never claim
the agent acted autonomously (plan section 2.3 / 3.1.5 wording).

mitmproxy itself is an optional dependency: pip install "agent-detector[gateway]".
"""
