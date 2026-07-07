"""Tests for config auto-discovery and environment overrides."""

from __future__ import annotations

import os

from atlas_atomic.core.config import Config


def _clear_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("ATLAS_"):
            monkeypatch.delenv(k, raising=False)


def test_explicit_config_wins(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    cfg_file = tmp_path / "my.yaml"
    cfg_file.write_text("provider:\n  name: ollama\n  model: llama3\n", encoding="utf-8")
    cfg = Config.load(str(cfg_file))
    assert cfg.provider.name == "ollama"
    assert cfg.source == str(cfg_file)


def test_atlas_config_env_is_discovered(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    cfg_file = tmp_path / "env.yaml"
    cfg_file.write_text("trials: 4\n", encoding="utf-8")
    monkeypatch.setenv("ATLAS_CONFIG", str(cfg_file))
    cfg = Config.load(None)
    assert cfg.trials == 4
    assert cfg.source == str(cfg_file)


def test_well_known_name_is_discovered(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "atlas.yaml").write_text("reports_dir: out\n", encoding="utf-8")
    cfg = Config.load(None)
    assert cfg.reports_dir == "out"
    assert cfg.source.endswith("atlas.yaml")


def test_no_config_falls_back_to_defaults(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.chdir(tmp_path)  # empty dir, nothing to discover
    cfg = Config.load(None)
    assert cfg.source is None
    assert cfg.provider.name == "mock"


def test_env_overrides_apply(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ATLAS_PROVIDER", "anthropic")
    monkeypatch.setenv("ATLAS_TRIALS", "5")
    monkeypatch.setenv("ATLAS_REPORTS_DIR", "siem-out")
    cfg = Config.load(None)
    assert cfg.provider.name == "anthropic"
    assert cfg.trials == 5
    assert cfg.reports_dir == "siem-out"


def test_missing_explicit_config_returns_none_source(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    cfg = Config.load(str(tmp_path / "does-not-exist.yaml"))
    assert cfg.source is None  # falls back rather than crashing
