"""Tests for the YAML loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from atlas_atomic.core.models import Role
from atlas_atomic.runner.loader import (
    TestValidationError,
    discover_tests,
    load_test_file,
    validate_tests,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def test_load_minimal_prompts(tmp_path):
    p = _write(
        tmp_path,
        "t.yaml",
        """
        id: T-1
        name: Minimal
        technique: Prompt Injection
        prompts:
          - hello
          - world
        evaluation:
          refusal_expected: true
        """,
    )
    test = load_test_file(p)
    assert test.id == "T-1"
    assert len(test.turns) == 2
    assert test.turns[0].prompt == "hello"
    assert test.evaluation.refusal_expected is True


def test_load_full_turns_with_tool_response(tmp_path):
    p = _write(
        tmp_path,
        "t.yaml",
        """
        id: T-2
        name: Turns
        technique: RAG Data Exfiltration
        turns:
          - prompt: summarize
            role: user
            tool_response: "poisoned doc"
            evaluation:
              not_contains: ["SECRET"]
        """,
    )
    test = load_test_file(p)
    assert test.turns[0].role is Role.USER
    assert test.turns[0].tool_response == "poisoned doc"
    assert test.turns[0].evaluation.not_contains == ["SECRET"]


def test_missing_required_field(tmp_path):
    p = _write(tmp_path, "bad.yaml", "name: no id\ntechnique: x\nprompts: [a]\n")
    with pytest.raises(TestValidationError):
        load_test_file(p)


def test_no_prompts_or_turns(tmp_path):
    p = _write(tmp_path, "bad.yaml", "id: X\nname: n\ntechnique: t\n")
    with pytest.raises(TestValidationError):
        load_test_file(p)


def test_discover_skips_invalid(tmp_path):
    _write(tmp_path, "good.yaml", "id: G\nname: n\ntechnique: t\nprompts: [a]\n")
    _write(tmp_path, "bad.yaml", "id: B\nname: n\n")  # missing technique/prompts
    tests = discover_tests(tmp_path)
    assert [t.id for t in tests] == ["G"]


def test_discover_deduplicates_ids(tmp_path):
    _write(tmp_path, "a.yaml", "id: DUP\nname: n\ntechnique: t\nprompts: [a]\n")
    _write(tmp_path, "b.yaml", "id: DUP\nname: n\ntechnique: t\nprompts: [a]\n")
    tests = discover_tests(tmp_path)
    assert len(tests) == 1


def test_shipped_examples_are_valid():
    errors = validate_tests(REPO_ROOT / "atomic_tests")
    assert errors == [], f"shipped example tests should validate: {errors}"


def test_shipped_examples_discoverable():
    tests = discover_tests(REPO_ROOT / "atomic_tests")
    ids = {t.id for t in tests}
    assert "ATLAS-PI-001" in ids
    assert len(tests) >= 8
