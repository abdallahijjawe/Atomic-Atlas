"""Tests for the reporting engine."""

from __future__ import annotations

import json

from atlas_atomic.core.models import TestResult, Verdict
from atlas_atomic.runner.reporter import (
    RunReport,
    render_html,
    render_json,
    render_junit,
    render_markdown,
    render_ndjson,
    write_report,
)


def _report() -> RunReport:
    report = RunReport(provider="mock", model="mock-model")
    report.results.append(
        TestResult(
            test_id="ATLAS-PI-001",
            name="Basic Prompt Injection",
            technique="Prompt Injection",
            category="prompt_injection",
            severity="high",
            atlas_technique_id="AML.T0051.000",
            provider="mock",
            model="mock-model",
            verdict=Verdict.PASS,
            reasoning="All checks passed.",
            transcript=[{"role": "user", "content": "hi"}],
            duration_seconds=0.01,
        )
    )
    report.results.append(
        TestResult(
            test_id="ATLAS-RAG-001",
            name="RAG Exfil",
            technique="RAG Data Exfiltration",
            category="rag",
            severity="critical",
            atlas_technique_id="AML.T0057",
            provider="mock",
            model="mock-model",
            verdict=Verdict.FAIL,
            reasoning="Leaked secret.",
        )
    )
    return report


def test_summary_counts():
    s = _report().summary
    assert s["total"] == 2 and s["PASS"] == 1 and s["FAIL"] == 1


def test_json_roundtrips():
    data = json.loads(render_json(_report()))
    assert data["summary"]["total"] == 2
    assert data["results"][0]["test_id"] == "ATLAS-PI-001"


def test_markdown_contains_verdicts():
    md = render_markdown(_report())
    assert "ATLAS-PI-001" in md and "PASS" in md and "FAIL" in md


def test_html_is_self_contained():
    html = render_html(_report())
    assert html.startswith("<!doctype html>")
    assert "ATLAS-PI-001" in html
    assert "http://" not in html.split("<style>")[0]  # no external refs in head


def test_write_report_all_formats(tmp_path):
    report = _report()
    for fmt, ext in [
        ("json", "json"),
        ("markdown", "md"),
        ("html", "html"),
        ("ndjson", "ndjson"),
        ("junit", "xml"),
    ]:
        path = write_report(report, tmp_path, fmt)
        assert path.exists() and path.suffix == f".{ext}"


def test_posture_at_risk_on_critical_fail():
    # A critical control failed -> AT-RISK posture.
    assert _report().posture == "AT-RISK"


def test_failures_by_severity():
    fbs = _report().failures_by_severity
    assert fbs["critical"] == 1 and fbs["high"] == 0


def test_ndjson_is_one_object_per_line():
    lines = [l for l in render_ndjson(_report()).splitlines() if l]
    assert len(lines) == 2
    rec = json.loads(lines[1])
    assert rec["severity"] == "critical" and rec["is_finding"] is True
    assert rec["atlas_technique_id"] == "AML.T0057"


def test_junit_maps_fail_to_failure():
    xml = render_junit(_report())
    assert xml.startswith("<?xml")
    assert 'failures="1"' in xml
    assert "<failure" in xml


def test_json_includes_posture_and_severity():
    data = json.loads(render_json(_report()))
    assert data["posture"] == "AT-RISK"
    assert data["failures_by_severity"]["critical"] == 1
    assert data["results"][0]["severity"] == "high"


def test_author_appears_in_every_format():
    from atlas_atomic.runner.reporter import render_junit, render_ndjson

    r = _report()
    assert r.author == "Abdalla Hijjawe"
    assert "Abdalla Hijjawe" in render_json(r)
    assert "Abdalla Hijjawe" in render_markdown(r)
    assert "Abdalla Hijjawe" in render_html(r)
    assert "Abdalla Hijjawe" in render_ndjson(r)
    assert "Abdalla Hijjawe" in render_junit(r)
