"""Smoke tests for the CLI commands (catch wiring bugs like a bad sort key)."""

from __future__ import annotations

from pathlib import Path

from atlas_atomic.runner.cli import main

REPO_ROOT = Path(__file__).resolve().parents[1]
TD = ["--tests-dir", str(REPO_ROOT / "atomic_tests")]


def test_list_runs(capsys):
    rc = main([*TD, "list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ATLAS-PI-001" in out
    assert "SEVERITY" in out
    assert "test(s)." in out


def test_mutators_runs(capsys):
    rc = main(["mutators"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "base64" in out and "homoglyph" in out


def test_validate_runs():
    assert main([*TD, "validate"]) == 0


def test_run_all_against_mock(capsys):
    rc = main([*TD, "run", "--all", "--provider", "mock"])
    out = capsys.readouterr().out
    assert rc == 0  # defended mock passes all -> no failures
    assert "RISK POSTURE" in out


def test_run_fuzz_expands(capsys):
    rc = main([*TD, "run", "--test", "ATLAS-PI-001", "--mutate",
               "--mutators", "base64,rot13"])
    out = capsys.readouterr().out
    assert "expanded 1 test(s) -> 3" in out
    assert rc in (0, 1)


def test_run_trials(capsys):
    main([*TD, "run", "--test", "ATLAS-PI-001", "--provider", "mock", "--trials", "3"])
    out = capsys.readouterr().out
    assert "ASR" in out


def test_run_defaults_to_all_without_selector(capsys):
    # A bare `run` (no --test/--technique/--all) should run everything.
    rc = main([*TD, "run", "--provider", "mock"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "RISK POSTURE" in out
    assert "ATLAS-PI-001" in out


def test_doctor_mock_is_ready(capsys):
    rc = main([*TD, "doctor"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "setup check" in out
    assert "Ready" in out


def test_unknown_provider_is_clean_error(capsys):
    # Must not raise a traceback -- clean message + usage exit code.
    rc = main([*TD, "run", "--all", "--provider", "bogus"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "Provider error" in err
