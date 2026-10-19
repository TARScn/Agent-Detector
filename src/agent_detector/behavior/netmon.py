"""Outbound connection collection and LLM-call matching (plan §3.1.4).

Connection-level evidence only: the OS tells us which process talks to which
destination; TLS keeps the content invisible unless traffic moves through an
authorized channel. A match proves "a call to a known LLM destination
happened", never what was said.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import psutil


def _clean(text: str) -> str:
    return text.encode("utf-8", "replace").decode("utf-8")


@dataclass(frozen=True)
class ConnInfo:
    pid: int
    process_name: str
    remote_ip: str
    remote_port: int


@dataclass(frozen=True)
class NetObservation:
    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    host: str            # domain (llm_api) or "Name:port" (local_model)
    match_kind: str      # "llm_api" | "local_model"
    confidence: str
    evidence: tuple[str, ...]


def collect_outbound() -> list[ConnInfo]:
    """ESTABLISHED outbound TCP connections with an owning pid (read-only)."""
    try:
        sockets = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError):
        return []
    result: list[ConnInfo] = []
    for sock in sockets:
        if sock.status != psutil.CONN_ESTABLISHED or not sock.raddr or not sock.pid:
            continue
        result.append(ConnInfo(pid=sock.pid, process_name="",
                               remote_ip=sock.raddr.ip, remote_port=sock.raddr.port))
    return result


def resolve_process_names(pids: set[int]) -> dict[int, str]:
    """Best-effort pid -> process name for the given snapshot of pids."""
    names: dict[int, str] = {}
    for pid in pids:
        try:
            names[pid] = _clean(psutil.Process(pid).name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return names


def is_loopback_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def match_llm_call(conn: ConnInfo, rules, dns_cache: dict[str, str]) -> NetObservation | None:
    """Match one connection against behavior rules; None means not LLM-related.

    Order matters: loopback destinations are matched by known model ports even
    if a DNS name exists; remote destinations are matched by resolving the IP
    through the DNS cache against the known-LLM-host list (exact match).
    """
    if is_loopback_ip(conn.remote_ip):
        name = rules.model_port_name(conn.remote_port)
        if not name:
            return None
        return NetObservation(pid=conn.pid, process_name=conn.process_name,
                              remote_ip=conn.remote_ip, remote_port=conn.remote_port,
                              host=f"{name}:{conn.remote_port}", match_kind="local_model",
                              confidence="medium", evidence=("local_model_port",))
    host = dns_cache.get(conn.remote_ip, "")
    if host and host in rules.known_llm_hosts:
        return NetObservation(pid=conn.pid, process_name=conn.process_name,
                              remote_ip=conn.remote_ip, remote_port=conn.remote_port,
                              host=host, match_kind="llm_api", confidence="medium",
                              evidence=("dns_cache", "known_llm_host"))
    return None
