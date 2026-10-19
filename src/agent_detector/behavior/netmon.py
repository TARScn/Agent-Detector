"""Outbound connection collection and LLM-call matching (plan §3.1.4).

Connection-level evidence only: the OS tells us which process talks to which
destination; TLS keeps the content invisible unless traffic moves through an
authorized channel. A match proves "a call to a known LLM destination
happened", never what was said.
"""
from __future__ import annotations

import ipaddress
import socket
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
    asset_id: str | None = None   # resolved at match time when provable (local_model)


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


def _system_resolve(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, 443)})
    except (socket.gaierror, OSError):
        return []


def resolve_known_hosts(hosts, resolver=None) -> dict[str, str]:
    """Resolve each known LLM host via the system resolver -> {ip: host}.

    Closes the Chromium/DoH blind spot: apps with built-in resolvers never
    populate the OS DNS cache, so the monitor establishes the ip -> host
    mapping for the known-host list itself. Shared-CDN addresses may make
    this an over-approximation; the evidence tag records the provenance.
    """
    resolver = resolver or _system_resolve
    mapping: dict[str, str] = {}
    for host in hosts:
        try:
            ips = resolver(host)
        except Exception:  # one bad lookup must not abort the sweep
            continue
        for ip in ips:
            mapping.setdefault(ip, host)
    return mapping


def match_llm_call(conn: ConnInfo, rules,
                   dns_hosts: dict[str, tuple[tuple[str, str], ...]],
                   model_ports: dict[int, str | None] | None = None) -> NetObservation | None:
    """Match one connection against behavior rules; None means not LLM-related.

    Loopback destinations require BOTH a known model port in the rules and
    scan corroboration (`model_ports` maps port -> asset_id of an asset the
    scanner identified as LLM_SERVICE) — a bare port match would flag any dev
    server that happens to sit on 8000. Remote destinations resolve the IP
    through retained name mappings ((host, origin) pairs) and require an
    exact known-LLM-host hit; the host name is the discriminator, and the
    evidence tag records whether the mapping was observed ("dns_cache") or
    proactively resolved ("proactive_resolve").
    """
    if is_loopback_ip(conn.remote_ip):
        name = rules.model_port_name(conn.remote_port)
        if not name or model_ports is None or conn.remote_port not in model_ports:
            return None
        return NetObservation(pid=conn.pid, process_name=conn.process_name,
                              remote_ip=conn.remote_ip, remote_port=conn.remote_port,
                              host=f"{name}:{conn.remote_port}", match_kind="local_model",
                              confidence="medium", evidence=("local_model_port", "scan_asset"),
                              asset_id=model_ports[conn.remote_port])
    for host, origin in dns_hosts.get(conn.remote_ip, ()):
        if host in rules.known_llm_hosts:
            source = "dns_cache" if origin == "cache" else "proactive_resolve"
            return NetObservation(pid=conn.pid, process_name=conn.process_name,
                                  remote_ip=conn.remote_ip, remote_port=conn.remote_port,
                                  host=host, match_kind="llm_api", confidence="medium",
                                  evidence=(source, "known_llm_host"))
    return None
