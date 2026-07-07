"""Runtime configuration model and loader.

Configuration selects which provider to run tests against and tunes execution.
Switching from a mock target to a real one (OpenAI/Anthropic/Ollama) is purely a
config change -- no code changes -- satisfying the provider-swap requirement.

Precedence (highest wins):
    1. Explicit overrides passed in code / CLI flags
    2. Environment variables (e.g. ATLAS_PROVIDER, OPENAI_API_KEY)
    3. Values in the YAML config file
    4. Built-in defaults

Config file discovery (when no ``--config`` is passed): the ``ATLAS_CONFIG``
environment variable, then ``atlas.yaml`` / ``atlas.yml`` / ``config/config.yaml``
in the current directory. This lets a user drop a config next to their project
and simply run ``atlas run`` with no flags.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Files that `atlas` auto-loads when no --config is given, in priority order.
DEFAULT_CONFIG_NAMES: tuple[str, ...] = (
    "atlas.yaml",
    "atlas.yml",
    "config/config.yaml",
    "config/config.yml",
)


@dataclass(slots=True)
class ProviderConfig:
    """Configuration for the target provider under test."""

    name: str = "mock"  # mock | openai | anthropic | ollama
    model: str = "mock-model"
    api_key_env: str = ""  # env var name holding the key, e.g. "OPENAI_API_KEY"
    base_url: str | None = None
    temperature: float = 0.0
    max_tokens: int = 1024
    timeout_seconds: float = 60.0
    # Free-form extra kwargs forwarded to the provider client.
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def api_key(self) -> str | None:
        if not self.api_key_env:
            return None
        return os.environ.get(self.api_key_env)


@dataclass(slots=True)
class JudgeConfig:
    """Optional configuration for the LLM-as-a-judge evaluator."""

    enabled: bool = False
    provider: str = "mock"
    model: str = "mock-model"
    api_key_env: str = ""
    # When True, the judge re-adjudicates *ambiguous* rule-based verdicts (e.g. a
    # response that both looks like a refusal and trips a keyword check), reducing
    # false positives without a per-test `llm_judge` rule.
    adjudicate_ambiguous: bool = False


@dataclass(slots=True)
class Config:
    """Top-level runtime configuration."""

    provider: ProviderConfig = field(default_factory=ProviderConfig)
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    tests_dir: str = "atomic_tests"
    reports_dir: str = "reports"
    log_level: str = "INFO"
    # Number of times to run each test. Models are non-deterministic, so N>1
    # yields an attack-success-rate rather than a single lucky pass/fail.
    trials: int = 1
    # Path of the config file this was loaded from (None = defaults + env only).
    # Purely informational, so the CLI can tell the user what it picked up.
    source: str | None = None

    # ------------------------------------------------------------------ #
    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        provider_raw = dict(raw.get("provider", {}))
        judge_raw = dict(raw.get("judge", {}))
        cfg = cls(
            provider=ProviderConfig(**provider_raw) if provider_raw else ProviderConfig(),
            judge=JudgeConfig(**judge_raw) if judge_raw else JudgeConfig(),
            tests_dir=raw.get("tests_dir", "atomic_tests"),
            reports_dir=raw.get("reports_dir", "reports"),
            log_level=raw.get("log_level", "INFO"),
            trials=int(raw.get("trials", 1)),
        )
        cfg.apply_env_overrides()
        return cfg

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        """Load config from ``path``, else an auto-discovered file, else env+defaults.

        When ``path`` is None we look for ``ATLAS_CONFIG`` then the well-known
        names in :data:`DEFAULT_CONFIG_NAMES`, so ``atlas run`` works with no
        flags once a config file exists in the project.
        """

        resolved = cls.resolve_config_path(path)
        if resolved is not None:
            cfg = cls.from_file(resolved)
            cfg.source = str(resolved)
            return cfg
        cfg = cls()
        cfg.apply_env_overrides()
        return cfg

    @staticmethod
    def resolve_config_path(path: str | Path | None) -> Path | None:
        """Return the config file to load, or None to fall back to env+defaults."""

        if path:
            p = Path(path)
            return p if p.exists() else None
        env = os.environ.get("ATLAS_CONFIG")
        if env and Path(env).exists():
            return Path(env)
        for name in DEFAULT_CONFIG_NAMES:
            cand = Path(name)
            if cand.exists():
                return cand
        return None

    def apply_env_overrides(self) -> None:
        """Apply ATLAS_* environment overrides on top of file/default values."""

        if v := os.environ.get("ATLAS_PROVIDER"):
            self.provider.name = v
        if v := os.environ.get("ATLAS_MODEL"):
            self.provider.model = v
        if v := os.environ.get("ATLAS_BASE_URL"):
            self.provider.base_url = v
        if v := os.environ.get("ATLAS_LOG_LEVEL"):
            self.log_level = v
        if v := os.environ.get("ATLAS_TESTS_DIR"):
            self.tests_dir = v
        if v := os.environ.get("ATLAS_REPORTS_DIR"):
            self.reports_dir = v
        if v := os.environ.get("ATLAS_TRIALS"):
            try:
                self.trials = max(1, int(v))
            except ValueError:
                pass
