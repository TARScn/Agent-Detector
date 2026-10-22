from agent_detector.detection.llm_intel import BehaviorRules, load_rules


def test_packaged_rules_load():
    loaded = load_rules()
    assert loaded.rules.revision >= 1
    assert "api.anthropic.com" in loaded.rules.known_llm_hosts
    assert loaded.rules.model_port_name(11434) == "Ollama"
    assert loaded.errors == []


def test_host_normalization_is_lowercase_exact():
    rules = BehaviorRules.model_validate({"known_llm_hosts": ["API.Example.COM.", " api.openai.com "]})
    assert set(rules.known_llm_hosts) == {"api.example.com", "api.openai.com"}


def test_broken_external_file_falls_back_to_packaged(tmp_path):
    (tmp_path / "llm_apis.yaml").write_text("known_llm_hosts: [ok-host\n  bad: [", encoding="utf-8")
    loaded = load_rules(extra_dir=tmp_path)
    assert loaded.errors and "llm_apis.yaml" in loaded.errors[0]["file"]
    assert "api.anthropic.com" in loaded.rules.known_llm_hosts  # packaged fallback


def test_external_rules_override_packaged(tmp_path):
    (tmp_path / "llm_apis.yaml").write_text(
        "revision: 7\nknown_llm_hosts: [internal-llm.corp]\n"
        "known_model_ports: [{port: 9999, name: Internal}]", encoding="utf-8")
    loaded = load_rules(extra_dir=tmp_path)
    assert loaded.rules.revision == 7
    assert loaded.rules.known_llm_hosts == ("internal-llm.corp",)
    assert loaded.rules.model_port_name(9999) == "Internal"
    assert loaded.rules.model_port_name(11434) is None
    assert loaded.errors == []


def test_unknown_fields_rejected():
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        BehaviorRules.model_validate({"known_llm_hosts": [], "surprise": True})
