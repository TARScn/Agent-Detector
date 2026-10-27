"""Pydantic models validating fingerprint rule files.

Unknown keys are rejected so typos in hand-edited YAML fail loudly at load
time instead of silently changing detection behavior.
"""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_detector.core.enums import AssetType, VersionSource


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class SignatureRule(_Strict):
    """One generic command-line signature (cheap first-pass screening)."""

    name: str
    asset_type: AssetType
    pattern: str

    @field_validator("pattern")
    @classmethod
    def _regex_compiles(cls, value: str) -> str:
        re.compile(value)
        return value


class SignatureSet(_Strict):
    kind: Literal["signature_set"]
    rules: list[SignatureRule]


class PackageProbe(_Strict):
    package: str
    confidence: float = 0.9


class PathProbe(_Strict):
    path: str
    confidence: float = 0.8


class JsonKeyProbe(_Strict):
    path: str
    keys_any: list[str]
    confidence: float = 0.9


class InstallSpec(_Strict):
    npm_packages: list[PackageProbe] = Field(default_factory=list)
    paths: list[PathProbe] = Field(default_factory=list)
    dirs: list[PathProbe] = Field(default_factory=list)


class ConfigSpec(_Strict):
    json_files: list[JsonKeyProbe] = Field(default_factory=list)
    existing_files: list[PathProbe] = Field(default_factory=list)


class VersionStep(_Strict):
    """One version source; steps are tried top to bottom, first hit wins.

    ``executable_version_flag`` runs the product's own ``--version``-style
    probe: read-only by design (no state change), and bounded — it only runs
    after passive evidence already claimed the binary as this product
    (INSTALLED), always executes the argv written in this rule (never
    anything taken from live processes), without a shell and under a hard
    timeout. Only the first regex match is kept as the version.
    """

    from_: Literal["npm_package_json", "semver_dir_entries",
                   "executable_version_flag"] = Field(alias="from")
    dirs: list[str] = Field(default_factory=list)
    path: str = ""                    # executable_version_flag: the binary to probe
    argv: list[str] = Field(default_factory=lambda: ["--version"])
    pattern: str = r"\d+\.\d+\.\d+"   # first match wins; use a group to narrow
    timeout_ms: int = 5000
    source: VersionSource = VersionSource.UNKNOWN
    confidence: float = 0.8

    @field_validator("pattern")
    @classmethod
    def _pattern_compiles(cls, value: str) -> str:
        re.compile(value)
        return value

    @field_validator("timeout_ms")
    @classmethod
    def _timeout_bounded(cls, value: int) -> int:
        if not 500 <= value <= 15000:
            raise ValueError("timeout_ms must be between 500 and 15000")
        return value


class ProcessSpec(_Strict):
    executable_names: list[str] = Field(default_factory=list)
    cmdline_tokens: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)
    confidence: float = 0.85

    @field_validator("exclude_patterns")
    @classmethod
    def _patterns_compile(cls, value: list[str]) -> list[str]:
        for pattern in value:
            re.compile(pattern)
        return value


class ConfidenceSpec(_Strict):
    """How the three evidence classes combine into one asset confidence."""

    base: float = 0.5
    installed: float = 0.2
    configured: float = 0.2
    running: float = 0.25
    cap: float = 0.95


class LlmSource(_Strict):
    """One config file to probe for the Agent's LLM base model and provider.

    ``fields`` maps a field name (reserved: ``model`` / ``base_url`` /
    ``provider_id``) to a dotted path into the parsed document. A path may
    reference an earlier field with ``{name}`` (Codex: the provider table is
    picked by the ``model_provider`` value) and may contain ``*`` to expand
    across all keys at that level (OpenCode: a dict of providers).
    """

    path: str
    format: Literal["json", "jsonc", "toml"] = "json"
    fields: dict[str, str] = Field(default_factory=dict)
    default_provider: str = ""


class LlmSpec(_Strict):
    """Where to read the Agent's LLM base model and API provider from."""

    sources: list[LlmSource] = Field(default_factory=list)


class DependencyProbe(_Strict):
    """Package-name probe against a project's scanned dependency metadata.

    Names are matched after PEP 503 normalization (case / ``-`` ``_`` ``.``
    equivalent). ``any`` hits when at least one package is present, ``all``
    requires every one of them.
    """

    any: list[str] = Field(default_factory=list)
    all: list[str] = Field(default_factory=list)


class FrameworkRule(_Strict):
    """Declarative detection rule for one self-built agent framework.

    Evaluated against dependency metadata resolved per project directory, not
    against process names: self-built agents hide inside ordinary interpreter
    processes (design §2.2/§3.1). A dependency hit alone proves the framework
    *environment*, never a running Agent — states stay honest downstream.
    """

    kind: Literal["framework_rule"]
    id: str
    name: str
    vendor: str = ""
    revision: int = 1
    runtimes: list[Literal["python", "node"]] = Field(default_factory=lambda: ["python"])
    dependencies: DependencyProbe = Field(default_factory=DependencyProbe)
    confidence: ConfidenceSpec = Field(default_factory=ConfidenceSpec)


class ContainerSpec(_Strict):
    """How the same product is laid out inside a Docker container.

    The Docker channel reads these with the read-only container client loop
    (sources/docker_agents.py); paths are container-internal absolutes.
    ``package`` names the directory under each ``npm_roots`` entry (defaults
    to the rule id). ``image_keywords`` feed candidate screening.
    """

    package: str = ""
    npm_roots: list[str] = Field(default_factory=list)
    config_json: list[JsonKeyProbe] = Field(default_factory=list)
    config_existing: list[str] = Field(default_factory=list)
    process_tokens: list[str] = Field(default_factory=list)
    image_keywords: list[str] = Field(default_factory=list)


class ClientRule(_Strict):
    """Full detection rule for one agent client product."""

    kind: Literal["client_rule"]
    id: str
    name: str
    asset_type: AssetType
    revision: int = 1
    confidence: ConfidenceSpec = Field(default_factory=ConfidenceSpec)
    install: InstallSpec = Field(default_factory=InstallSpec)
    config: ConfigSpec = Field(default_factory=ConfigSpec)
    version: list[VersionStep] = Field(default_factory=list)
    process: ProcessSpec | None = None
    llm: LlmSpec | None = None
    container: ContainerSpec | None = None
