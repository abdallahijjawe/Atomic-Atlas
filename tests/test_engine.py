"""End-to-end engine tests against the mock provider."""

from __future__ import annotations

from pathlib import Path

from atlas_atomic.core.config import ProviderConfig
from atlas_atomic.core.models import Verdict
from atlas_atomic.providers import build_provider
from atlas_atomic.runner.engine import Engine
from atlas_atomic.runner.evaluator import Evaluator
from atlas_atomic.runner.loader import discover_tests, load_test_file

REPO_ROOT = Path(__file__).resolve().parents[1]
PI_001 = REPO_ROOT / "atomic_tests" / "prompt_injection" / "ATLAS-PI-001.yaml"


def _engine(**options) -> Engine:
    provider = build_provider(ProviderConfig(name="mock", options=options))
    return Engine(provider, Evaluator())


def test_defended_target_passes_injection_test():
    test = load_test_file(PI_001)
    result = _engine().run(test)
    assert result.verdict is Verdict.PASS
    assert result.transcript  # conversation was recorded


def test_vulnerable_target_fails_injection_test():
    test = load_test_file(PI_001)
    result = _engine(vulnerable=True, canary="CANARY-SYS-PROMPT-7F3A").run(test)
    assert result.verdict is Verdict.FAIL


def test_multi_turn_state_is_preserved():
    jb = REPO_ROOT / "atomic_tests" / "jailbreaking" / "ATLAS-JB-001-multiturn.yaml"
    test = load_test_file(jb)
    result = _engine().run(test)
    # 3 user turns + 3 assistant replies + 1 system prompt.
    roles = [m["role"] for m in result.transcript]
    assert roles.count("user") == 3
    assert roles.count("assistant") == 3
    assert result.verdict is Verdict.PASS


def test_full_suite_passes_against_defended_mock():
    tests = discover_tests(REPO_ROOT / "atomic_tests")
    engine = _engine()
    verdicts = {t.id: engine.run(t).verdict for t in tests}
    fails = {tid: v for tid, v in verdicts.items() if v is Verdict.FAIL}
    assert not fails, f"defended mock should pass all shipped tests, got fails: {fails}"


def test_full_suite_fails_against_vulnerable_mock():
    tests = discover_tests(REPO_ROOT / "atomic_tests")
    engine = _engine(vulnerable=True, canary="CANARY-SYS-PROMPT-7F3A")
    verdicts = [engine.run(t).verdict for t in tests]
    # A vulnerable target should be caught failing at least one test.
    assert Verdict.FAIL in verdicts
