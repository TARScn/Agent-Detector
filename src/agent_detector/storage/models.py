"""SQLAlchemy entities for scan tasks, assets, snapshots and evidence (plan section 5.2).

Timestamps are stored as ISO-8601 UTC strings: SQLite has no native timezone
handling, and an explicit format avoids naive/aware ambiguity.
"""
from datetime import datetime, timezone

from sqlalchemy import (Float, ForeignKey, Index, Integer, String, Text,
                        UniqueConstraint, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Base(DeclarativeBase):
    pass


class ScanTaskRow(Base):
    __tablename__ = "scan_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mode: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="running")
    started_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    finished_at: Mapped[str | None] = mapped_column(String(48))
    stats_json: Mapped[str] = mapped_column(Text, default="{}")


class AssetRow(Base):
    """Stable asset identity across scans (plan section 5.3)."""

    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    asset_type: Mapped[str] = mapped_column(String(32))
    first_seen_at: Mapped[str] = mapped_column(String(48))
    last_seen_at: Mapped[str] = mapped_column(String(48))


class AssetSnapshotRow(Base):
    __tablename__ = "asset_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.asset_id"), index=True)
    states_json: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    version: Mapped[str] = mapped_column(String(64))
    version_source: Mapped[str] = mapped_column(String(32))
    running_pids_json: Mapped[str] = mapped_column(Text, default="[]")
    listening_ports_json: Mapped[str] = mapped_column(Text, default="[]")
    detector: Mapped[str] = mapped_column(String(64))


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_tasks.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.asset_id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    created_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class BehaviorEventRow(Base):
    """Unified behavior/telemetry event feed (design section 7).

    One table, many channels: ``source`` says which observer wrote the row
    (``netmon`` outbound LLM connections, ``auditd``/``poll`` Linux system
    behavior, ``sysmon`` Windows process/file/network events, ``native_hook``
    Agent tool calls). A row carries *evidence*, never conversation content or
    file bodies; ``asset_id`` stays empty when nothing could be proven.
    """

    __tablename__ = "behavior_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    observed_at: Mapped[str] = mapped_column(String(48), index=True)
    source: Mapped[str] = mapped_column(String(32), default="netmon")
    agent_label: Mapped[str] = mapped_column(String(80), index=True)
    asset_id: Mapped[str | None] = mapped_column(String(96))
    flow_id: Mapped[str] = mapped_column(String(64))
    upstream_host: Mapped[str] = mapped_column(String(255))
    protocol: Mapped[str] = mapped_column(String(16), index=True)
    event_type: Mapped[str] = mapped_column(String(48))
    operation: Mapped[str] = mapped_column(String(100))
    confidence: Mapped[str] = mapped_column(String(16))
    endpoint: Mapped[str] = mapped_column(String(150))
    protocol_version: Mapped[str | None] = mapped_column(String(30))
    component_version: Mapped[str | None] = mapped_column(String(30))
    model: Mapped[str | None] = mapped_column(String(90))
    tool: Mapped[str | None] = mapped_column(String(90))
    http_status: Mapped[int | None] = mapped_column(Integer)
    # System behavior columns (added after V0.1 shipped; see database.ensure_schema):
    pid: Mapped[int | None] = mapped_column(Integer)
    ppid: Mapped[int | None] = mapped_column(Integer)
    process_name: Mapped[str | None] = mapped_column(String(80))
    target: Mapped[str | None] = mapped_column(String(512))
    result: Mapped[str | None] = mapped_column(String(24))
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    # V0.2 columns: correlation identity and pre-execution decision.
    instance_id: Mapped[str | None] = mapped_column(String(96))
    session_id: Mapped[str | None] = mapped_column(String(96), index=True)
    process_guid: Mapped[str | None] = mapped_column(String(96))
    risk_level: Mapped[str | None] = mapped_column(String(16), index=True)
    decision: Mapped[str | None] = mapped_column(String(16))
    execution_status: Mapped[str | None] = mapped_column(String(24))
    policy_id: Mapped[str | None] = mapped_column(String(64))
    # eBPF (Tetragon) channel: container hex-ID prefix when the process ran in
    # a container; empty for host processes.
    container_id: Mapped[str | None] = mapped_column(String(96))
    # P0-C: actor and target are independent roles. ``asset_id`` stays as the
    # legacy actor column for existing readers; actor_asset_id is the new
    # explicit field. A model-service port belongs in target_asset_id and
    # must never be written to asset_id.
    scope_key: Mapped[str | None] = mapped_column(String(96), index=True)
    actor_asset_id: Mapped[str | None] = mapped_column(String(96), index=True)
    actor_instance_id: Mapped[str | None] = mapped_column(String(96))
    actor_process_key: Mapped[str | None] = mapped_column(String(96), index=True)
    target_asset_id: Mapped[str | None] = mapped_column(String(96), index=True)
    target_endpoint_id: Mapped[str | None] = mapped_column(String(96), index=True)
    target_instance_id: Mapped[str | None] = mapped_column(String(96))
    attribution_method: Mapped[str | None] = mapped_column(String(64))
    attribution_state: Mapped[str | None] = mapped_column(String(24))
    source_event_uid: Mapped[str | None] = mapped_column(String(96))
    # P2.3: MCP server name parsed from mcp__<server>__<tool>.
    mcp_server: Mapped[str | None] = mapped_column(String(96), index=True)
    # An event is unique per source event; replaying the same source row is
    # idempotent, while two real connections remain two events.
    __table_args__ = (
        Index("uq_behavior_source_event", "source", "source_event_uid",
              unique=True),
    )


class AgentAssetRow(Base):
    """Logical Agent asset (design section 3.4): one row per discovered Agent.

    Shares ``assets.asset_id`` with the discovery snapshot tables so the
    detector stays the single source of identity; this table adds what the
    dashboard needs — capability matrix, hook state and protection status.
    """

    __tablename__ = "agent_assets"

    asset_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    agent_type: Mapped[str] = mapped_column(String(48), index=True)
    name: Mapped[str] = mapped_column(String(120))
    vendor: Mapped[str] = mapped_column(String(80), default="")
    version: Mapped[str] = mapped_column(String(64), default="UNKNOWN")
    version_source: Mapped[str] = mapped_column(String(32), default="unknown")
    states_json: Mapped[str] = mapped_column(Text, default="[]")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    executable: Mapped[str | None] = mapped_column(String(512))
    config_paths_json: Mapped[str] = mapped_column(Text, default="[]")
    mcp_servers_json: Mapped[str] = mapped_column(Text, default="[]")
    llm_endpoints_json: Mapped[str] = mapped_column(Text, default="[]")
    app_id: Mapped[str | None] = mapped_column(String(96))
    # Docker channel (Docker Core): where this asset lives. origin stays
    # "host" for everything the classic channels found.
    origin: Mapped[str] = mapped_column(String(16), default="host")
    container_id: Mapped[str | None] = mapped_column(String(96))
    # Post-scan verification (design §6.3): active = seen in the latest scan,
    # inactive = self-built whose project dir still exists but no live process,
    # removed = re-verified gone (uninstalled / path deleted / sighting over).
    status: Mapped[str] = mapped_column(String(24), default="active")
    capabilities_json: Mapped[str] = mapped_column(Text, default="{}")
    protection_status: Mapped[str] = mapped_column(String(24), default="UNKNOWN")
    hook_state: Mapped[str] = mapped_column(String(24), default="UNKNOWN")
    hook_detail_json: Mapped[str] = mapped_column(Text, default="{}")
    notes_json: Mapped[str] = mapped_column(Text, default="[]")
    first_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class ApplicationRow(Base):
    """Self-built agent application (design §6.3): one resolved project directory.

    The Application sits between Host and Agent: one process runs one app, the
    app may embed several frameworks. ``app_id`` is shared with the discovery
    snapshot tables by convention (like agent_assets.asset_id), no SQL FK.
    """

    __tablename__ = "applications"

    app_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    root_path: Mapped[str] = mapped_column(String(512))
    runtime: Mapped[str] = mapped_column(String(32), default="unknown")
    environment_path: Mapped[str | None] = mapped_column(String(512))
    entrypoint: Mapped[str | None] = mapped_column(String(512))
    entry_kind: Mapped[str] = mapped_column(String(32), default="cwd")
    container_id: Mapped[str | None] = mapped_column(String(96))
    # Same lifecycle as agent_assets.status: active / inactive / removed.
    status: Mapped[str] = mapped_column(String(24), default="active")
    first_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class ApplicationComponentRow(Base):
    """One AI-relevant package seen in an application's dependency metadata."""

    __tablename__ = "application_components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    app_id: Mapped[str] = mapped_column(String(96), index=True)
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[str] = mapped_column(String(64), default="UNKNOWN")
    version_source: Mapped[str] = mapped_column(String(32), default="unknown")
    source_path: Mapped[str | None] = mapped_column(String(512))
    first_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class AgentInstanceRow(Base):
    """One running Agent process. Windows reuses PIDs, so identity is
    ``instance_id`` = hash(asset_id, pid, process start time)."""

    __tablename__ = "agent_instances"

    instance_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(96), index=True)
    agent_type: Mapped[str] = mapped_column(String(48), index=True)
    pid: Mapped[int] = mapped_column(Integer, index=True)
    ppid: Mapped[int | None] = mapped_column(Integer)
    process_guid: Mapped[str | None] = mapped_column(String(96))
    process_name: Mapped[str] = mapped_column(String(120), default="")
    executable: Mapped[str | None] = mapped_column(String(512))
    cmdline: Mapped[str] = mapped_column(Text, default="")
    cwd: Mapped[str | None] = mapped_column(String(512))
    parent_chain_json: Mapped[str] = mapped_column(Text, default="[]")
    # Docker channel: container-internal process of a container-origin asset.
    origin: Mapped[str] = mapped_column(String(16), default="host")
    container_id: Mapped[str | None] = mapped_column(String(96))
    status: Mapped[str] = mapped_column(String(24), default="running")
    evidence_json: Mapped[str] = mapped_column(Text, default="[]")
    started_at: Mapped[str | None] = mapped_column(String(48))
    last_seen_at: Mapped[str | None] = mapped_column(String(48))


class AgentSessionRow(Base):
    """Native Agent session (hook session_id); links tool calls to one run."""

    __tablename__ = "agent_sessions"

    session_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    asset_id: Mapped[str | None] = mapped_column(String(96), index=True)
    agent_type: Mapped[str] = mapped_column(String(48), index=True)
    instance_id: Mapped[str | None] = mapped_column(String(96))
    source: Mapped[str] = mapped_column(String(32), default="native_hook")
    cwd: Mapped[str | None] = mapped_column(String(512))
    last_tool: Mapped[str | None] = mapped_column(String(90))
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[str | None] = mapped_column(String(48))
    last_event_at: Mapped[str | None] = mapped_column(String(48))
    ended_at: Mapped[str | None] = mapped_column(String(48))


class SecurityPolicyRow(Base):
    """Declarative policy as stored (mirror of the packaged policies.yaml)."""

    __tablename__ = "security_policies"

    policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    scope: Mapped[str] = mapped_column(String(24), default="tool_call")
    decision: Mapped[str] = mapped_column(String(16), default="audit")
    risk_level: Mapped[str] = mapped_column(String(16), default="medium")
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    conditions_json: Mapped[str] = mapped_column(Text, default="{}")
    reason: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class SecurityAlertRow(Base):
    """Raised when a behavior event or a hook verdict crosses the risk bar."""

    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[str] = mapped_column(String(48), index=True, default=utc_now_iso)
    asset_id: Mapped[str | None] = mapped_column(String(96), index=True)
    agent_type: Mapped[str | None] = mapped_column(String(48))
    agent_label: Mapped[str] = mapped_column(String(80), default="")
    session_id: Mapped[str | None] = mapped_column(String(96))
    event_id: Mapped[int | None] = mapped_column(Integer, index=True)
    policy_id: Mapped[str | None] = mapped_column(String(64))
    risk_level: Mapped[str] = mapped_column(String(16), default="medium")
    decision: Mapped[str] = mapped_column(String(16), default="audit")
    status: Mapped[str] = mapped_column(String(24), default="open")
    title: Mapped[str] = mapped_column(String(200), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    resolved_at: Mapped[str | None] = mapped_column(String(48))


# ---------------------------------------------------------------------------
# P0-A identity foundation. These tables are written in shadow mode: the
# legacy read path (assets / agent_assets / applications) is untouched until
# P0-D switches readers through entity_aliases.
# ---------------------------------------------------------------------------


class EntityRow(Base):
    """Canonical logical asset. The id is opaque and never recomputed."""

    __tablename__ = "entities"

    entity_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    entity_kind: Mapped[str] = mapped_column(String(48), index=True)
    # host_key or engine_key; the key itself also encodes this, but the column
    # makes grouping/filtering possible without parsing canonical JSON.
    scope_key: Mapped[str] = mapped_column(String(96), index=True, default="")
    created_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class EntityKeyRow(Base):
    """Versioned strong key -> entity mapping.

    Only one open key per (identity_version, key_type, canonical_key) is
    allowed; a canonicalization change closes the old key first and writes the
    new one beside it, so lookups by either version keep working.
    """

    __tablename__ = "entity_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_type: Mapped[str] = mapped_column(String(32), index=True)
    canonical_key: Mapped[str] = mapped_column(String(96))
    identity_version: Mapped[int] = mapped_column(Integer, default=1)
    entity_id: Mapped[str] = mapped_column(ForeignKey("entities.entity_id"),
                                           index=True)
    valid_from: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    valid_to: Mapped[str | None] = mapped_column(String(48))
    confidence_basis: Mapped[str] = mapped_column(String(96), default="")

    __table_args__ = (
        Index("uq_entity_key_open", "identity_version", "key_type",
              "canonical_key", unique=True,
              sqlite_where=text("valid_to IS NULL")),
    )


class EntityAliasRow(Base):
    """Legacy id -> canonical entity, so P0-D can switch readers safely."""

    __tablename__ = "entity_aliases"

    old_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    entity_id: Mapped[str] = mapped_column(ForeignKey("entities.entity_id"),
                                           index=True)
    reason: Mapped[str] = mapped_column(String(96), default="")
    # OK = safe alias; AMBIGUOUS = the old id was seen pointing at different
    # entities and must not be silently merged.
    status: Mapped[str] = mapped_column(String(16), default="OK")
    created_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class HostIdentityRow(Base):
    __tablename__ = "host_identities"

    host_key: Mapped[str] = mapped_column(String(96), primary_key=True)
    identity_version: Mapped[int] = mapped_column(Integer, default=1)
    identity_basis: Mapped[str] = mapped_column(String(48), default="unresolved")
    installation_id: Mapped[str] = mapped_column(String(96), default="")
    trust_state: Mapped[str] = mapped_column(String(24), default="UNVERIFIED")
    detector_local: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    identity_verified_at: Mapped[str | None] = mapped_column(String(48))


class HostIdentityClaimRow(Base):
    """Hashed platform anchor supporting a host identity (never raw ids)."""

    __tablename__ = "host_identity_claims"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_key: Mapped[str] = mapped_column(ForeignKey("host_identities.host_key"),
                                          index=True)
    claim_type: Mapped[str] = mapped_column(String(48))
    value_hash: Mapped[str] = mapped_column(String(96))
    source: Mapped[str] = mapped_column(String(160), default="")
    observed_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)

    __table_args__ = (
        UniqueConstraint("host_key", "claim_type", "value_hash",
                         name="uq_host_identity_claim"),
    )


class DockerEngineRow(Base):
    __tablename__ = "docker_engines"

    engine_key: Mapped[str] = mapped_column(String(96), primary_key=True)
    engine_id_claim: Mapped[str | None] = mapped_column(String(128))
    endpoint_aliases_json: Mapped[str] = mapped_column(Text, default="[]")
    engine_host_key: Mapped[str | None] = mapped_column(String(96), index=True)
    binding_state: Mapped[str] = mapped_column(String(24), default="UNVERIFIED")
    first_seen: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen: Mapped[str] = mapped_column(String(48), default=utc_now_iso)


class EngineHostBindingRow(Base):
    """Verified engine -> host mapping; absence means the host is unknown."""

    __tablename__ = "engine_host_bindings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    engine_key: Mapped[str] = mapped_column(ForeignKey("docker_engines.engine_key"),
                                            index=True)
    host_key: Mapped[str] = mapped_column(ForeignKey("host_identities.host_key"),
                                          index=True)
    binding_state: Mapped[str] = mapped_column(String(24), default="UNVERIFIED")
    evidence: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)

    __table_args__ = (
        UniqueConstraint("engine_key", "host_key", name="uq_engine_host_binding"),
    )


class EndpointRow(Base):
    """Stable network endpoint identity (P0-C). ``observed_at`` is not part
    of the key; observation windows belong to the event/binding."""

    __tablename__ = "endpoints"

    endpoint_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    scope_key: Mapped[str] = mapped_column(String(96), index=True)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    address: Mapped[str] = mapped_column(String(64), default="")
    port: Mapped[int] = mapped_column(Integer)
    namespace: Mapped[str] = mapped_column(String(96), default="host")
    owner_entity_id: Mapped[str | None] = mapped_column(String(96), index=True)
    valid_from: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    valid_to: Mapped[str | None] = mapped_column(String(48))

    __table_args__ = (
        Index("uq_endpoint_open", "scope_key", "protocol", "address", "port",
              "namespace", unique=True,
              sqlite_where=text("valid_to IS NULL")),
    )


class EndpointBindingRow(Base):
    """Host endpoint -> container endpoint mapping with a validity window."""

    __tablename__ = "endpoint_bindings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.endpoint_id"),
                                                  index=True)
    container_endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("endpoints.endpoint_id"), index=True)
    container_id: Mapped[str] = mapped_column(String(96), index=True)
    binding_source: Mapped[str] = mapped_column(String(48),
                                                default="docker_published_port")
    valid_from: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    valid_to: Mapped[str | None] = mapped_column(String(48))

    __table_args__ = (
        Index("uq_endpoint_binding_open", "host_endpoint_id", unique=True,
              sqlite_where=text("valid_to IS NULL")),
    )


class CoverageScopeRow(Base):
    """One completeness claim for one scan scope (P0-B)."""

    __tablename__ = "coverage_scopes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(Integer, index=True)
    scope_type: Mapped[str] = mapped_column(String(48))
    scope_key: Mapped[str] = mapped_column(String(256))
    source: Mapped[str] = mapped_column(String(32), default="")
    own_status: Mapped[str] = mapped_column(String(16))
    budget: Mapped[int] = mapped_column(Integer, default=0)
    scanned_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[int] = mapped_column(Integer, default=0)
    error_codes_json: Mapped[str] = mapped_column(Text, default="[]")
    started_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    finished_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)

    __table_args__ = (
        UniqueConstraint("run_id", "scope_type", "scope_key",
                         name="uq_coverage_scope_run"),
    )


class CoverageScopeEdgeRow(Base):
    __tablename__ = "coverage_scope_edges"

    parent_id: Mapped[int] = mapped_column(
        ForeignKey("coverage_scopes.id"), primary_key=True)
    child_id: Mapped[int] = mapped_column(
        ForeignKey("coverage_scopes.id"), primary_key=True, index=True)


class CoveragePredicateStatusRow(Base):
    __tablename__ = "coverage_scope_predicates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scope_id: Mapped[int] = mapped_column(ForeignKey("coverage_scopes.id"),
                                          index=True)
    predicate: Mapped[str] = mapped_column(String(64))
    own_status: Mapped[str] = mapped_column(String(16))
    error_code: Mapped[str | None] = mapped_column(String(160))

    __table_args__ = (
        UniqueConstraint("scope_id", "predicate",
                         name="uq_coverage_scope_predicate"),
    )


class RemovalCandidateRow(Base):
    """Absence candidate; never a deletion. CONFIRMED_ABSENT still archives."""

    __tablename__ = "removal_candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(Integer, index=True)
    asset_id: Mapped[str] = mapped_column(String(96), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(96), index=True)
    entity_kind: Mapped[str] = mapped_column(String(48), default="UNKNOWN")
    predicate: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="UNVERIFIED")
    reason: Mapped[str] = mapped_column(Text, default="")
    coverage_refs_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    updated_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)

    __table_args__ = (
        UniqueConstraint("run_id", "asset_id", "predicate",
                         name="uq_removal_candidate_run"),
    )


class ObservationRow(Base):
    """Immutable normalized observation (P1 evidence ledger)."""

    __tablename__ = "observations"

    observation_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    source_event_uid: Mapped[str] = mapped_column(String(160))
    scope_key: Mapped[str] = mapped_column(String(96), index=True, default="")
    fact_type: Mapped[str] = mapped_column(String(48))
    normalized_payload_json: Mapped[str] = mapped_column(Text, default="{}")
    payload_digest: Mapped[str] = mapped_column(String(96), default="")
    observed_at: Mapped[str] = mapped_column(String(48), index=True)
    collection_run_id: Mapped[int] = mapped_column(Integer, index=True)
    normalizer_version: Mapped[int] = mapped_column(Integer, default=1)
    retention_class: Mapped[str] = mapped_column(String(24),
                                                 default="raw_short")

    __table_args__ = (
        UniqueConstraint("source", "source_event_uid",
                         name="uq_observation_source_event"),
    )


class ClaimRow(Base):
    """A revisable interpretation backed by observations."""

    __tablename__ = "claims"

    claim_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    subject_ref: Mapped[str] = mapped_column(String(96), index=True)
    predicate: Mapped[str] = mapped_column(String(48))
    object_ref: Mapped[str] = mapped_column(String(160), default="")
    polarity: Mapped[str] = mapped_column(String(16), default="support")
    evidence_class: Mapped[str] = mapped_column(String(8), default="E2")
    verification_method: Mapped[str] = mapped_column(String(48), default="")
    rule_id: Mapped[str] = mapped_column(String(64), default="")
    rule_digest: Mapped[str] = mapped_column(String(96), default="")
    rule_generation: Mapped[int] = mapped_column(Integer, default=0)
    collection_run_id: Mapped[int] = mapped_column(Integer, index=True)
    coverage_scope_id: Mapped[int | None] = mapped_column(Integer, index=True)
    observed_at: Mapped[str] = mapped_column(String(48))
    valid_from: Mapped[str] = mapped_column(String(48))
    valid_to: Mapped[str | None] = mapped_column(String(48))
    status: Mapped[str] = mapped_column(String(16), default="supported",
                                        index=True)
    supersedes_claim_id: Mapped[str | None] = mapped_column(String(96))

    __table_args__ = (
        UniqueConstraint("subject_ref", "predicate", "object_ref", "rule_id",
                         "rule_digest", "collection_run_id",
                         name="uq_claim_key"),
        Index("ix_claim_current", "subject_ref", "predicate", "status"),
    )


class ClaimEvidenceRow(Base):
    __tablename__ = "claim_evidence"

    claim_id: Mapped[str] = mapped_column(ForeignKey("claims.claim_id"),
                                          primary_key=True)
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("observations.observation_id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(16), default="supports")


class RuleRevisionRow(Base):
    __tablename__ = "rule_revisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    digest: Mapped[str] = mapped_column(String(96))
    source_path: Mapped[str] = mapped_column(String(512), default="")
    loaded_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)

    __table_args__ = (
        UniqueConstraint("rule_id", "digest", name="uq_rule_revision"),
    )


class EntitySnapshotRow(Base):
    """Per-generation user-facing status projection (P1)."""

    __tablename__ = "entity_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_id: Mapped[str] = mapped_column(String(96), index=True)
    generation_id: Mapped[int] = mapped_column(Integer, index=True)
    agent_status: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    status_basis_json: Mapped[str] = mapped_column(Text, default="{}")
    capability_tags_json: Mapped[str] = mapped_column(Text, default="[]")
    hook_state: Mapped[str] = mapped_column(String(24), default="UNKNOWN")
    removal_verdict: Mapped[str] = mapped_column(String(16), default="NONE")
    coverage_summary_json: Mapped[str] = mapped_column(Text, default="{}")
    projected_at: Mapped[str] = mapped_column(String(48), default=utc_now_iso)

    __table_args__ = (
        UniqueConstraint("entity_id", "generation_id",
                         name="uq_entity_snapshot_generation"),
    )


class ComponentRow(Base):
    """A framework / SDK / MCP component (not a top-level Agent entity)."""

    __tablename__ = "components"

    component_key: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), index=True)
    kind: Mapped[str] = mapped_column(String(32), default="FRAMEWORK")
    version: Mapped[str] = mapped_column(String(64), default="UNKNOWN")
    version_source: Mapped[str] = mapped_column(String(32), default="unknown")
    first_seen: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen: Mapped[str] = mapped_column(String(48), default=utc_now_iso)

    __table_args__ = (
        UniqueConstraint("name", "kind", name="uq_component_name_kind"),
    )


class ComponentRelationRow(Base):
    """Entity -> component dependency edge with its evidence claim."""

    __tablename__ = "component_relations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    entity_id: Mapped[str] = mapped_column(String(96), index=True)
    component_key: Mapped[str] = mapped_column(ForeignKey("components.component_key"),
                                               index=True)
    relation_type: Mapped[str] = mapped_column(String(24), default="DEPENDS_ON")
    version: Mapped[str] = mapped_column(String(64), default="UNKNOWN")
    version_source: Mapped[str] = mapped_column(String(32), default="unknown")
    status: Mapped[str] = mapped_column(String(16), default="confirmed")
    evidence_claim_id: Mapped[str | None] = mapped_column(String(96))
    valid_from: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    valid_to: Mapped[str | None] = mapped_column(String(48))

    __table_args__ = (
        Index("uq_component_relation_open", "entity_id", "component_key",
              "relation_type", unique=True,
              sqlite_where=text("valid_to IS NULL")),
    )


class RelationRow(Base):
    """Generic typed relation (entity/endpoint/component refs)."""

    __tablename__ = "relations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    from_ref: Mapped[str] = mapped_column(String(160), index=True)
    to_ref: Mapped[str] = mapped_column(String(160), index=True)
    relation_type: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(16), default="confirmed")
    evidence_claim_id: Mapped[str | None] = mapped_column(String(96))
    valid_from: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    valid_to: Mapped[str | None] = mapped_column(String(48))

    __table_args__ = (
        Index("uq_relation_open", "from_ref", "to_ref", "relation_type",
              unique=True, sqlite_where=text("valid_to IS NULL")),
    )


class ProcessBirthRow(Base):
    __tablename__ = "process_births"

    instance_key: Mapped[str] = mapped_column(String(96), primary_key=True)
    scope_key: Mapped[str] = mapped_column(String(96), index=True)
    platform: Mapped[str] = mapped_column(String(24))
    boot_identity: Mapped[str] = mapped_column(String(96), default="")
    pid_namespace_key: Mapped[str] = mapped_column(String(96), default="host")
    pid: Mapped[int] = mapped_column(Integer, index=True)
    native_birth_value: Mapped[str] = mapped_column(String(128))
    clock_domain: Mapped[str] = mapped_column(String(32))
    resolution: Mapped[str] = mapped_column(String(48), default="")
    canonical_start_ticks: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(32), default="psutil")
    verification_state: Mapped[str] = mapped_column(String(24), default="candidate")
    process_guid: Mapped[str | None] = mapped_column(String(96))
    first_seen: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
    last_seen: Mapped[str] = mapped_column(String(48), default=utc_now_iso)
