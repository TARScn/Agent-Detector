"""LLM base-model probe tests: the packaged YAML llm section drives extraction
against fabricated config files. Proves the rule data (not code) decides where
to read, and that secret-shaped values are never captured."""
import json

from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.discovery.sources.llm_config import (endpoints_for,
                                                 load_provider_map,
                                                 resolve_provider)
from agent_detector.core.models import HostFacts, ProcessInfo


def rule_by_id(rule_id):
    return next(r for r in load_rules().client_rules if r.id == rule_id)


def make_facts(processes=(), hostname="host-a"):
    return HostFacts(hostname=hostname, processes=tuple(processes), sockets=())


def test_codex_toml_provider_ref_resolution(tmp_path):
    """{provider_id} 引用：按 model_provider 的值查 provider 表拿 base_url。"""
    home = tmp_path / "home"
    state = home / ".codex"
    state.mkdir(parents=True)
    (state / "config.toml").write_text(
        'model = "glm-5.3-flash"\nmodel_provider = "custom"\n'
        '\n[model_providers.custom]\nname = "zhipu"\n'
        'base_url = "https://open.bigmodel.cn/api/v1"\n', encoding="utf-8")
    endpoints = endpoints_for(rule_by_id("codex-cli"), home=home)
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.model == "glm-5.3-flash"
    assert endpoint.base_url == "https://open.bigmodel.cn/api/v1"
    assert endpoint.provider == "智谱 Z.ai"
    assert endpoint.provider_id == "custom"
    assert endpoint.source.endswith("config.toml")


def test_opencode_jsonc_star_expansion(tmp_path):
    """provider 字典 + * 展开：每个 provider 一条端点，模型挂到每条上。"""
    home = tmp_path / "home"
    config_dir = home / ".config" / "opencode"
    config_dir.mkdir(parents=True)
    (config_dir / "opencode.jsonc").write_text(
        '// 用户配置\n{"model": "glm-5.3-flash",\n'
        ' "provider": {\n'
        '   "zai": {"options": {"baseURL": "https://open.bigmodel.cn/api/paas/v4"}},\n'
        '   "relay": {"options": {"baseURL": "http://127.0.0.1:9/v1"}}}}',
        encoding="utf-8")
    endpoints = endpoints_for(rule_by_id("opencode"), home=home)
    assert len(endpoints) == 2
    by_url = {e.base_url: e for e in endpoints}
    assert by_url["https://open.bigmodel.cn/api/paas/v4"].provider == "智谱 Z.ai"
    assert by_url["https://open.bigmodel.cn/api/paas/v4"].model == "glm-5.3-flash"
    assert by_url["http://127.0.0.1:9/v1"].provider == "本地中转（上游未知）"


def test_claude_settings_env_endpoint(tmp_path):
    home = tmp_path / "home"
    claude_dir = home / ".claude"
    claude_dir.mkdir(parents=True)
    (claude_dir / "settings.json").write_text(json.dumps({
        "env": {"ANTHROPIC_BASE_URL": "https://api.anthropic.com",
                "ANTHROPIC_AUTH_TOKEN": "sk-ant-secret-value-12345678"}}),
        encoding="utf-8")
    endpoints = endpoints_for(rule_by_id("claude-code"), home=home)
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.base_url == "https://api.anthropic.com"
    assert endpoint.provider == "Anthropic"
    # 密钥不在任何被提取的字段里
    serialized = json.dumps([e.to_dict() for e in endpoints])
    assert "sk-ant-secret-value" not in serialized


def test_cursor_default_provider_without_base_url(tmp_path):
    home = tmp_path / "home"
    cursor_dir = home / ".cursor"
    cursor_dir.mkdir(parents=True)
    (cursor_dir / "cli-config.json").write_text(
        json.dumps({"model": {"modelId": "default", "displayModelId": "auto"}}),
        encoding="utf-8")
    endpoints = endpoints_for(rule_by_id("cursor"), home=home)
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.model == "auto"
    assert endpoint.base_url == ""
    assert endpoint.provider == "Cursor 自营（账号托管）"


def test_rule_without_llm_section_yields_nothing(tmp_path):
    """没有 llm 段的规则不产生端点（claude 规则必有 llm 段，用临时规则验证）。"""
    home = tmp_path / "home"
    home.mkdir()
    rule = rule_by_id("codex-cli").model_copy(deep=True, update={"llm": None})
    assert endpoints_for(rule, home=home) == []


def test_missing_config_files_yield_nothing(tmp_path):
    assert endpoints_for(rule_by_id("codex-cli"), home=tmp_path / "home") == []


def test_secret_shaped_values_are_never_captured(tmp_path):
    """路径直接指向密钥形值时，提取结果必须为空而不是把密钥带出来。"""
    home = tmp_path / "home"
    state = home / ".codex"
    state.mkdir(parents=True)
    (state / "config.toml").write_text(
        'model = "c5cd6301581143b387533b5bb58bf37f.PK02pDgqpOSKxvXx"\n',
        encoding="utf-8")
    endpoints = endpoints_for(rule_by_id("codex-cli"), home=home)
    assert endpoints == []


def test_provider_map_and_resolution():
    providers = load_provider_map()
    assert ("bigmodel.cn", "智谱 Z.ai") in providers
    assert resolve_provider("https://open.bigmodel.cn/api/v1", providers) == "智谱 Z.ai"
    assert resolve_provider("http://127.0.0.1:15721/v1", providers) == "本地中转（上游未知）"
    assert resolve_provider("https://example.internal/v1", providers) == ""
    assert resolve_provider("not a url", providers) == ""


def test_packaged_rules_all_declare_llm_sources():
    """四个 client rule 都应有 llm 段——本功能的承诺是规则驱动、全覆盖。"""
    for rule_id in ("claude-code", "codex-cli", "cursor", "opencode"):
        rule = rule_by_id(rule_id)
        assert rule.llm is not None and rule.llm.sources, rule_id


def test_real_machine_inventory_includes_endpoints():
    """实机冒烟：本机 Codex/OpenCode 应能读出智谱端点（无网络请求）。"""
    from agent_detector.monitoring.collectors.host.process import collect_host_facts
    from agent_detector.discovery.scanner.build import build_detectors
    from agent_detector.discovery.scanner.inventory import InventoryBuilder

    builder = InventoryBuilder()
    facts = collect_host_facts()
    detected = []
    for detector in build_detectors():
        detected.extend(detector.detect(facts))
    items = builder.apply_scan(_session_stub(), detected, facts)
    endpoints = {item["agent_type"]: item.get("llm_endpoints") for item in items}
    codex = endpoints.get("codex_cli") or []
    assert any(e["model"] == "glm-5.3-flash" for e in codex)
    assert any("bigmodel" in e["base_url"] or e["provider"] == "本地中转（上游未知）"
               for e in codex)


class _SessionStub:
    """InventoryBuilder.apply_scan 只用 repository.upsert_asset/upsert_instances；
    实机冒烟不落库，桩掉写路径。"""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def get(self, *_):
        return None

    def add(self, *_):
        return None

    def scalars(self, *_):
        return []

    def execute(self, *_):
        return []


def _session_stub():
    return _SessionStub()


def test_process_info_unused_guard():
    """占位：保持与其它 detector 测试相同的 import 面（HostFacts/ProcessInfo）。"""
    assert make_facts().processes == ()
