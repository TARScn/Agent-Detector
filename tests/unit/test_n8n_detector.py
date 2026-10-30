"""n8n 宿主 client_rule：npm 全局安装 + 数据目录 + 进程命令行（跨 OS 布局）。

宿主布局（Windows %APPDATA%\\npm\\node_modules、Linux /usr/local|usr/lib、
npm root -g 兜底）由 engine.npm_global_roots 承担；本文件用注入的
npm_global_root 验证规则本身的行为。
"""
from __future__ import annotations

import json

from agent_detector.core.enums import AssetState, AssetType, VersionSource
from agent_detector.core.models import HostFacts, ProcessInfo
from agent_detector.discovery.fingerprints.engine import ClientRuleDetector
from agent_detector.discovery.fingerprints.loader import load_rules
from agent_detector.discovery.sources.agents import load_agent_matrix


def n8n_rule():
    return next(rule for rule in load_rules().client_rules if rule.id == "n8n")


def detector_for(home):
    # 显式 npm root + 关闭活探测，测试与真机状态隔离
    return ClientRuleDetector(n8n_rule(), home=home,
                              npm_global_root=home / "npm-root" / "node_modules",
                              run_npm_lookup=False)


def build_home(tmp_path, *, version="2.44.7", package=True, data_dir=True):
    home = tmp_path / "home"
    if package:
        package_dir = home / "npm-root" / "node_modules" / "n8n"
        package_dir.mkdir(parents=True)
        (package_dir / "package.json").write_text(
            json.dumps({"name": "n8n", "version": version}), encoding="utf-8")
    if data_dir:
        (home / ".n8n").mkdir(parents=True)
        (home / ".n8n" / "database.sqlite").write_bytes(b"")
    return home


def facts(*processes):
    return HostFacts(hostname="host-a", processes=tuple(processes), sockets=())


def test_full_install_running(tmp_path):
    home = build_home(tmp_path)
    proc = ProcessInfo(
        pid=201, name="node.exe",
        cmdline=("node", "C:/Users/u/AppData/Roaming/npm/node_modules/n8n/bin/n8n",
                 "start"))
    (asset,) = detector_for(home).detect(facts(proc))
    assert asset.name == "n8n"
    assert asset.asset_type is AssetType.AGENT_PLATFORM
    assert {AssetState.INSTALLED, AssetState.CONFIGURED,
            AssetState.RUNNING} <= asset.states
    assert asset.version.value == "2.44.7"
    assert asset.version.source is VersionSource.PACKAGE_METADATA
    assert asset.running_pids == [201]
    # database.sqlite 只作存在性证据，永不读取内容
    assert any("database.sqlite" in path for path in asset.config_paths)
    assert all(e.kind.value != "file_content_keys" for e in asset.evidence)


def test_package_uninstalled_but_data_dir_remains(tmp_path):
    # 包卸载、数据目录残留 → 目录仍证明安装过；无进程 → 不挂 RUNNING
    home = build_home(tmp_path, package=False)
    (asset,) = detector_for(home).detect(facts())
    assert AssetState.INSTALLED in asset.states
    assert AssetState.CONFIGURED in asset.states
    assert AssetState.RUNNING not in asset.states
    assert asset.version.value == "UNKNOWN"  # 无来源即 UNKNOWN，禁止猜测


def test_bare_word_in_arguments_is_not_running_evidence(tmp_path):
    home = build_home(tmp_path)
    proc = ProcessInfo(pid=202, name="python.exe",
                       cmdline=("python", "backup.py", "--label", "n8n"))
    (asset,) = detector_for(home).detect(facts(proc))
    assert AssetState.RUNNING not in asset.states
    assert asset.running_pids == []


def test_clean_home_claims_nothing(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    proc = ProcessInfo(pid=203, name="node.exe", cmdline=("node", "server.js"))
    assert detector_for(home).detect(facts(proc)) == []


def test_matrix_entry_and_no_hook_adapter():
    entry = load_agent_matrix().for_type("n8n")
    assert entry is not None and entry.name == "n8n"
    assert entry.discovery == "P1" and entry.protect == "PLANNED"
