"""Rule loader tests: packaged files parse, bad files are isolated errors,
and external rule directories override packaged rules by id."""
import yaml

from agent_detector.discovery.fingerprints.loader import load_rules


def test_packaged_rules_load_cleanly():
    loaded = load_rules()
    assert loaded.errors == []
    assert [r.id for r in loaded.client_rules] == ["claude-code", "codex-cli",
                                                    "cursor", "dify", "hermes",
                                                    "n8n", "openclaw", "opencode",
                                                    "zcode"]
    # 自建框架走依赖识别（framework_rule），签名通道已于 2026-11-02 退役 ——
    # 宽松命令行正则拿不到版本、还会撞上参数/路径里的同名单词（Dify 误报事故）。
    assert {"langchain", "langgraph", "langflow"} <= {r.id for r in loaded.framework_rules}


def test_broken_rule_file_is_isolated(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "broken.yaml").write_text("kind: client_rule\nid: [unclosed", encoding="utf-8")
    (rules_dir / "unknown_kind.yaml").write_text("kind: mystery\n", encoding="utf-8")
    (rules_dir / "bad_framework.yaml").write_text(
        yaml.safe_dump({"kind": "framework_rule", "id": "x", "name": "X",
                        "dependencies": "nope"}),
        encoding="utf-8")
    loaded = load_rules(extra_dir=rules_dir)
    assert len(loaded.errors) == 3
    assert not loaded.client_rules or loaded.client_rules[0].id == "claude-code"
    assert len(loaded.framework_rules) >= 5  # packaged set still intact


def test_external_dir_overrides_packaged_rule_by_id(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    override = {
        "kind": "client_rule",
        "id": "claude-code",
        "name": "Claude Code (site override)",
        "asset_type": "AGENT_CLIENT",
        "process": {"executable_names": ["site-claude"]},
    }
    (rules_dir / "claude_code.yaml").write_text(yaml.safe_dump(override), encoding="utf-8")
    loaded = load_rules(extra_dir=rules_dir)
    claude = [r for r in loaded.client_rules if r.id == "claude-code"]
    assert len(claude) == 1  # overridden, not duplicated
    assert claude[0].name == "Claude Code (site override)"
    assert claude[0].process.executable_names == ["site-claude"]
