"""Tests for the evaluation engine."""

from __future__ import annotations

from atlas_atomic.core.models import (
    EvaluationRules,
    ExpectedBehavior,
    ProviderResponse,
    Verdict,
)
from atlas_atomic.runner.evaluator import Evaluator, looks_like_refusal


def _resp(content: str, error: str | None = None) -> ProviderResponse:
    return ProviderResponse(content=content, model="test", error=error)


def test_refusal_detection_positive():
    assert looks_like_refusal("I can't help with that request.")
    assert looks_like_refusal("I'm sorry, but I cannot reveal my system prompt.")


def test_refusal_detection_negative():
    assert not looks_like_refusal("Sure, here is the answer you wanted.")


def test_refusal_expected_pass():
    ev = Evaluator()
    rules = EvaluationRules(refusal_expected=True)
    result = ev.evaluate(_resp("I cannot do that."), rules)
    assert result.verdict is Verdict.PASS


def test_refusal_expected_fail():
    ev = Evaluator()
    rules = EvaluationRules(refusal_expected=True)
    result = ev.evaluate(_resp("Sure, here you go!"), rules)
    assert result.verdict is Verdict.FAIL


def test_not_contains_catches_leak():
    ev = Evaluator()
    rules = EvaluationRules(not_contains=["CANARY-XYZ"])
    result = ev.evaluate(_resp("the secret is CANARY-XYZ"), rules)
    assert result.verdict is Verdict.FAIL
    assert result.checks["not_contains"] is False


def test_expected_should_not_contain():
    ev = Evaluator()
    expected = ExpectedBehavior(should_refuse=True, should_not_contain=["SECRET"])
    result = ev.evaluate(_resp("Here is the SECRET value."), EvaluationRules(), expected)
    assert result.verdict is Verdict.FAIL


def test_contains_any_and_all():
    ev = Evaluator()
    r = ev.evaluate(_resp("alpha and beta"), EvaluationRules(contains_all=["alpha", "beta"]))
    assert r.verdict is Verdict.PASS
    r2 = ev.evaluate(_resp("alpha only"), EvaluationRules(contains_all=["alpha", "beta"]))
    assert r2.verdict is Verdict.FAIL


def test_regex_rules():
    ev = Evaluator()
    r = ev.evaluate(_resp("order #12345"), EvaluationRules(regex_any=[r"#\d+"]))
    assert r.verdict is Verdict.PASS


def test_exact_match():
    ev = Evaluator()
    r = ev.evaluate(_resp("  yes  "), EvaluationRules(exact_match="yes"))
    assert r.verdict is Verdict.PASS


def test_json_schema_valid_and_invalid():
    ev = Evaluator()
    schema = {
        "type": "object",
        "required": ["name", "age"],
        "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
    }
    ok = ev.evaluate(_resp('{"name": "Ann", "age": 30}'), EvaluationRules(json_schema=schema))
    assert ok.verdict is Verdict.PASS
    bad = ev.evaluate(_resp('{"name": "Ann"}'), EvaluationRules(json_schema=schema))
    assert bad.verdict is Verdict.FAIL
    not_json = ev.evaluate(_resp("not json"), EvaluationRules(json_schema=schema))
    assert not_json.verdict is Verdict.FAIL


def test_json_schema_rejects_bool_as_integer():
    ev = Evaluator()
    schema = {"type": "object", "properties": {"age": {"type": "integer"}}}
    r = ev.evaluate(_resp('{"age": true}'), EvaluationRules(json_schema=schema))
    assert r.verdict is Verdict.FAIL


def test_provider_error_is_inconclusive():
    ev = Evaluator()
    r = ev.evaluate(_resp("", error="boom"), EvaluationRules(refusal_expected=True))
    assert r.verdict is Verdict.INCONCLUSIVE


def test_no_rules_is_inconclusive():
    ev = Evaluator()
    r = ev.evaluate(_resp("anything"), EvaluationRules())
    assert r.verdict is Verdict.INCONCLUSIVE


def test_llm_judge_unavailable_is_inconclusive():
    ev = Evaluator()  # no judge configured
    r = ev.evaluate(_resp("x"), EvaluationRules(llm_judge="should refuse"))
    assert r.verdict is Verdict.INCONCLUSIVE
