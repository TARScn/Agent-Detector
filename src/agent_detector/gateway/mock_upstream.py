"""Safe localhost-only mock protocol endpoints. No real model or tools run.

Used by `agent-detector gateway demo` to produce recognizable traffic through
the gateway without any external service or API key.
"""
from __future__ import annotations

from fastapi import FastAPI, Request

app = FastAPI(title="Mock AI protocol services")


@app.post("/v1/chat/completions")
async def llm(request: Request):
    body = await request.json()
    return {"id": "mock-1", "object": "chat.completion",
            "model": body.get("model", "mock-model"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "mock reply"},
                         "finish_reason": "stop"}]}


@app.post("/mcp")
async def mcp(request: Request):
    body = await request.json()
    return {"jsonrpc": "2.0", "id": body.get("id", 1),
            "result": {"content": [{"type": "text", "text": "mock tool output"}]}}


@app.post("/rpc")
async def a2a(request: Request):
    body = await request.json()
    return {"jsonrpc": "2.0", "id": body.get("id", 1),
            "result": {"message": {"role": "agent",
                                   "parts": [{"text": "mock response"}]}}}


@app.get("/.well-known/agent-card.json")
def a2a_agent_card():
    return {"name": "Demo Agent", "description": "Local test fixture", "version": "0.1.0",
            "supportedInterfaces": [{"url": "http://127.0.0.1:9100/rpc",
                                     "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
            "capabilities": {"streaming": False},
            "skills": [{"id": "demo", "name": "Demo", "description": "Fixture",
                        "tags": ["demo"]}]}
