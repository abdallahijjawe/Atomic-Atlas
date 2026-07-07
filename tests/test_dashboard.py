"""Tests for the trend dashboard."""

from __future__ import annotations

import json

from atlas_atomic.core.models import TestResult, Verdict
from atlas_atomic.runner.dashboard import (
    load_run_points,
    render_dashboard,
    write_dashboard,
)
from atlas_atomic.runner.reporter import RunReport, render_json


def _report(started, pass_ids, fail_specs) -> RunReport:
    """fail_specs: list of (test_id, severity)."""
    report = RunReport(provider="mock", model="mock-model", started_at=started)
    for tid in pass_ids:
        report.results.append(
            TestResult(
                test_id=tid, name=tid, technique="t", category="c",
                severity="high", provider="mock", model="mock-model",
                verdict=Verdict.PASS, reasoning="ok",
            )
        )
    for tid, sev in fail_specs:
        report.results.append(
            TestResult(
                test_id=tid, name=tid, technique="t", category="c",
                severity=sev, provider="mock", model="mock-model",
                verdict=Verdict.FAIL, reasoning="leak",
            )
        )
    return report


def _write(tmp_path, name, report):
    (tmp_path / name).write_text(render_json(report), encoding="utf-8")


def test_load_run_points_sorted_and_parsed(tmp_path):
    _write(tmp_path, "r2.json", _report("2026-07-02T10:00:00+00:00", ["a", "b"], [("c", "high")]))
    _write(tmp_path, "r1.json", _report("2026-07-01T10:00:00+00:00", ["a"], [("b", "critical"), ("c", "high")]))
    points = load_run_points(tmp_path)
    assert [p.timestamp for p in points] == [
        "2026-07-01T10:00:00+00:00",
        "2026-07-02T10:00:00+00:00",
    ]
    assert points[0].posture == "AT-RISK"          # critical fail
    assert points[0].pass_rate == pytest_approx(1 / 3 * 100)
    assert points[1].severity_fails["high"] == 1


def test_load_skips_non_report_json(tmp_path):
    (tmp_path / "junk.json").write_text('{"hello": "world"}', encoding="utf-8")
    (tmp_path / "bad.json").write_text("not json", encoding="utf-8")
    _write(tmp_path, "ok.json", _report("2026-07-01T10:00:00+00:00", ["a"], []))
    points = load_run_points(tmp_path)
    assert len(points) == 1


def test_render_is_self_contained_html(tmp_path):
    _write(tmp_path, "r1.json", _report("2026-07-01T10:00:00+00:00", ["a"], [("b", "high")]))
    _write(tmp_path, "r2.json", _report("2026-07-02T10:00:00+00:00", ["a", "b"], []))
    points = load_run_points(tmp_path)
    html = render_dashboard(points)
    assert html.startswith("<!doctype html>")
    assert "<svg" in html                          # charts rendered
    assert "Posture timeline" in html
    assert "SECURE" in html                        # latest run all-pass
    assert "http://" not in html.split("</head>")[0]  # no external assets


def test_render_empty_is_graceful():
    html = render_dashboard([])
    assert "No run reports found" in html


def test_write_dashboard(tmp_path):
    _write(tmp_path, "r1.json", _report("2026-07-01T10:00:00+00:00", ["a"], []))
    out = write_dashboard(tmp_path, tmp_path / "dash.html")
    assert out.exists()
    assert "<svg" in out.read_text(encoding="utf-8")


def pytest_approx(v):
    import pytest

    return pytest.approx(v, abs=0.01)
