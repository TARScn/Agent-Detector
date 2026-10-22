from agent_detector.discovery.identity import build_asset_id, normalize_path


def test_normalize_path_unifies_separators_and_drive_case():
    windows_style = normalize_path(r"C:\Users\Bob\.claude")
    unix_style = normalize_path("C:/Users/Bob/.claude")
    assert windows_style == unix_style
    assert "\\" not in windows_style


def test_normalize_path_strips_trailing_slash():
    assert normalize_path("/home/bob/") == normalize_path("/home/bob")


def test_asset_id_stable_and_scope_sensitive():
    first = build_asset_id("Host", "claude-code", "user-home:/home/bob")
    same = build_asset_id("host", "claude-code", "user-home:/home/bob")
    other_scope = build_asset_id("host", "claude-code", "user-home:/home/alice")
    assert first == same
    assert first != other_scope
    assert first.startswith("claude-code--")
