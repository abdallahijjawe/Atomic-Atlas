"""Reporting engine.

Renders a run's :class:`TestResult` list to JSON, Markdown, and self-contained
HTML. Each report includes, per test: id, technique, provider, model, the full
prompt/response transcript, the evaluation checks, the PASS/FAIL/INCONCLUSIVE
verdict, and timestamps.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape
from xml.sax.saxutils import quoteattr

from atlas_atomic import __author__, __version__
from atlas_atomic.core.logging import get_logger
from atlas_atomic.core.models import Severity, TestResult, Verdict, severity_rank

log = get_logger("reporter")

# Highest-to-lowest for iteration in summaries.
_SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def posture(report: "RunReport") -> str:
    """One-word risk posture for the run, for a SOC top-line banner.

    AT-RISK       -- a high/critical control failed (act now)
    NEEDS-REVIEW  -- a lower-severity control failed
    INCOMPLETE    -- nothing failed but some tests were inconclusive
    SECURE        -- every control behaved as expected
    """

    failed = [r for r in report.results if r.verdict is Verdict.FAIL]
    if any(severity_rank(r.severity) >= severity_rank(Severity.HIGH) for r in failed):
        return "AT-RISK"
    if failed:
        return "NEEDS-REVIEW"
    if any(r.verdict is Verdict.INCONCLUSIVE for r in report.results):
        return "INCOMPLETE"
    return "SECURE"


@dataclass(slots=True)
class RunReport:
    """A full run: metadata + per-test results, with summary counts."""

    provider: str
    model: str
    results: list[TestResult] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    author: str = __author__

    @property
    def summary(self) -> dict[str, int]:
        counts = {v.value: 0 for v in Verdict}
        for r in self.results:
            counts[r.verdict.value] += 1
        counts["total"] = len(self.results)
        return counts

    @property
    def failures_by_severity(self) -> dict[str, int]:
        """Count of FAILing tests grouped by severity (SOC prioritization)."""

        counts = {s.value: 0 for s in _SEVERITIES}
        for r in self.results:
            if r.verdict is Verdict.FAIL:
                counts[r.severity] = counts.get(r.severity, 0) + 1
        return counts

    @property
    def posture(self) -> str:
        return posture(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "author": self.author,
            "tool": f"ATLAS-Atomic v{__version__}",
            "provider": self.provider,
            "model": self.model,
            "started_at": self.started_at,
            "posture": self.posture,
            "summary": self.summary,
            "failures_by_severity": self.failures_by_severity,
            "results": [r.to_dict() for r in self.results],
        }


# --------------------------------------------------------------------------- #
def render_json(report: RunReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_markdown(report: RunReport) -> str:
    s = report.summary
    fbs = report.failures_by_severity
    sev_line = " | ".join(
        f"{name.upper()}: {fbs[name]}" for name in ("critical", "high", "medium", "low")
    )
    lines = [
        "# ATLAS-Atomic Report",
        "",
        f"> **Risk posture: {report.posture}**",
        "",
        f"- **Author:** {report.author}",
        f"- **Tool:** ATLAS-Atomic v{__version__}",
        f"- **Provider:** {report.provider}",
        f"- **Model:** {report.model}",
        f"- **Run started:** {report.started_at}",
        f"- **Total:** {s['total']} | "
        f"✅ PASS: {s['PASS']} | ❌ FAIL: {s['FAIL']} | "
        f"⚠️ INCONCLUSIVE: {s['INCONCLUSIVE']}",
        f"- **Failures by severity:** {sev_line}",
        "",
        "| Test ID | ATLAS | Severity | Technique | Verdict | Reasoning |",
        "|---------|-------|----------|-----------|---------|-----------|",
    ]
    for r in report.results:
        lines.append(
            f"| `{r.test_id}` | {r.atlas_technique_id or '-'} | {r.severity.upper()} "
            f"| {_md_cell(r.technique)} | {_verdict_badge(r.verdict)} "
            f"| {_md_cell(r.reasoning)} |"
        )
    lines.append("")

    for r in report.results:
        lines.append(f"## {_verdict_badge(r.verdict)} `{r.test_id}` — {r.name}")
        lines.append("")
        lines.append(f"- **Severity:** {r.severity.upper()}")
        lines.append(f"- **Technique:** {r.technique} ({r.atlas_technique_id or 'n/a'})")
        lines.append(f"- **Category:** {r.category}")
        lines.append(f"- **Provider / Model:** {r.provider} / {r.model}")
        lines.append(f"- **Duration:** {r.duration_seconds}s")
        lines.append(f"- **Reasoning:** {r.reasoning}")
        if r.error:
            lines.append(f"- **Error:** {r.error}")
        lines.append("")
        lines.append("**Transcript:**")
        lines.append("")
        for m in r.transcript:
            lines.append(f"- **{m['role']}:** {_md_cell(str(m['content']))}")
        lines.append("")
    lines.append("---")
    lines.append(f"_Report by {report.author} · ATLAS-Atomic v{__version__}_")
    return "\n".join(lines)


def render_html(report: RunReport) -> str:
    s = report.summary
    rows = []
    for r in report.results:
        transcript = "".join(
            f'<div class="msg {html.escape(m["role"])}">'
            f'<span class="role">{html.escape(m["role"])}</span>'
            f'<pre>{html.escape(str(m["content"]))}</pre></div>'
            for m in r.transcript
        )
        checks = html.escape(json.dumps(r.checks, indent=2, ensure_ascii=False))
        asr_span = (
            f'<span>ASR: {r.attack_success_rate:.0%} '
            f"({r.fail_count}/{r.trials})</span>"
            if r.trials > 1
            else ""
        )
        judge_span = "<span>judge-adjudicated</span>" if r.judge_adjudicated else ""
        rows.append(
            f"""
    <details class="test {r.verdict.value.lower()}">
      <summary>
        <span class="badge {r.verdict.value.lower()}">{r.verdict.value}</span>
        <span class="sev sev-{html.escape(r.severity)}">{html.escape(r.severity.upper())}</span>
        <code>{html.escape(r.test_id)}</code> — {html.escape(r.name)}
      </summary>
      <div class="meta">
        <span>Technique: {html.escape(r.technique)}</span>
        <span>ATLAS: {html.escape(r.atlas_technique_id or "n/a")}</span>
        <span>Category: {html.escape(r.category)}</span>
        <span>Model: {html.escape(r.model)}</span>
        <span>Duration: {r.duration_seconds}s</span>
        {asr_span}
        {judge_span}
      </div>
      <p class="reasoning">{html.escape(r.reasoning)}</p>
      <div class="transcript">{transcript}</div>
      <details class="checks"><summary>Evaluation checks</summary>
        <pre>{checks}</pre></details>
    </details>"""
        )
    body = "\n".join(rows)
    return _HTML_TEMPLATE.format(
        author=html.escape(report.author),
        version=html.escape(__version__),
        provider=html.escape(report.provider),
        model=html.escape(report.model),
        started=html.escape(report.started_at),
        posture=html.escape(report.posture),
        posture_class=report.posture.lower().replace("-", ""),
        total=s["total"],
        passed=s["PASS"],
        failed=s["FAIL"],
        inconclusive=s["INCONCLUSIVE"],
        rows=body,
    )


def render_ndjson(report: RunReport) -> str:
    """One JSON object per line -- a *findings* feed for SIEM/log ingestion.

    Each FAIL/INCONCLUSIVE becomes a finding record with severity, MITRE ATLAS
    id, verdict, and reasoning, ready to ship to Splunk/Elastic/etc. PASS results
    are emitted too (verdict=PASS) so you can track coverage, not just findings.
    """

    lines = []
    for r in report.results:
        lines.append(
            json.dumps(
                {
                    "timestamp": r.finished_at or report.started_at,
                    "event_type": "atlas_atomic.finding",
                    "author": report.author,
                    "tool": f"ATLAS-Atomic v{__version__}",
                    "test_id": r.test_id,
                    "name": r.name,
                    "technique": r.technique,
                    "atlas_technique_id": r.atlas_technique_id,
                    "category": r.category,
                    "severity": r.severity,
                    "verdict": r.verdict.value,
                    "is_finding": r.verdict.value == "FAIL",
                    "trials": r.trials,
                    "attack_success_rate": r.attack_success_rate,
                    "judge_adjudicated": r.judge_adjudicated,
                    "provider": r.provider,
                    "model": r.model,
                    "reasoning": r.reasoning,
                },
                ensure_ascii=False,
            )
        )
    return "\n".join(lines) + ("\n" if lines else "")


def render_junit(report: RunReport) -> str:
    """JUnit XML -- consumed natively by CI systems (Jenkins, GitLab, Azure...).

    A FAIL maps to a ``<failure>``, an INCONCLUSIVE to a ``<skipped>``, so
    pipelines can gate merges on control regressions.
    """

    s = report.summary
    cases = []
    for r in report.results:
        name = quoteattr(f"[{r.severity}] {r.name}")
        classname = quoteattr(f"{r.category}.{r.test_id}")
        time_attr = quoteattr(str(r.duration_seconds or 0))
        inner = ""
        if r.verdict is Verdict.FAIL:
            inner = (
                f"<failure message={quoteattr(r.reasoning)} "
                f"type={quoteattr(r.severity)}>{xml_escape(r.reasoning)}</failure>"
            )
        elif r.verdict is Verdict.INCONCLUSIVE:
            inner = f"<skipped message={quoteattr(r.reasoning)}/>"
        cases.append(
            f'    <testcase name={name} classname={classname} time={time_attr}>'
            f"{inner}</testcase>"
        )
    body = "\n".join(cases)
    props = (
        "  <properties>\n"
        f"    <property name=\"author\" value={quoteattr(report.author)}/>\n"
        f"    <property name=\"tool\" value={quoteattr('ATLAS-Atomic v' + __version__)}/>\n"
        "  </properties>"
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="atlas-atomic" tests="{s["total"]}" '
        f'failures="{s["FAIL"]}" skipped="{s["INCONCLUSIVE"]}" '
        f'hostname={quoteattr(report.model)}>\n{props}\n{body}\n</testsuite>\n'
    )


_RENDERERS = {
    "json": (render_json, "json"),
    "markdown": (render_markdown, "md"),
    "md": (render_markdown, "md"),
    "html": (render_html, "html"),
    "ndjson": (render_ndjson, "ndjson"),
    "junit": (render_junit, "xml"),
}


def _report_from_dict_safe(data: dict[str, Any]) -> RunReport:
    """Rebuild a :class:`RunReport` from its ``to_dict()`` form.

    Tolerant of older reports that predate the severity/posture fields --
    ``posture`` and ``failures_by_severity`` are computed properties, so they are
    re-derived from the per-result verdict + severity rather than read back.
    """

    report = RunReport(
        provider=data.get("provider", "unknown"),
        model=data.get("model", "unknown"),
        started_at=data.get("started_at", ""),
        author=data.get("author", __author__),
    )
    for r in data.get("results", []):
        report.results.append(
            TestResult(
                test_id=r.get("test_id", "?"),
                name=r.get("name", ""),
                technique=r.get("technique", ""),
                category=r.get("category", ""),
                severity=r.get("severity", "medium"),
                atlas_technique_id=r.get("atlas_technique_id", ""),
                provider=r.get("provider", report.provider),
                model=r.get("model", report.model),
                verdict=Verdict(r.get("verdict", "INCONCLUSIVE")),
                reasoning=r.get("reasoning", ""),
                trials=r.get("trials", 1),
                pass_count=r.get("pass_count", 0),
                fail_count=r.get("fail_count", 0),
                inconclusive_count=r.get("inconclusive_count", 0),
                attack_success_rate=r.get("attack_success_rate", 0.0),
                judge_adjudicated=r.get("judge_adjudicated", False),
                transcript=r.get("transcript", []),
                checks=r.get("checks", {}),
                error=r.get("error"),
                started_at=r.get("started_at", ""),
                finished_at=r.get("finished_at"),
                duration_seconds=r.get("duration_seconds"),
            )
        )
    return report


def write_report(report: RunReport, out_dir: str | Path, fmt: str) -> Path:
    """Render ``report`` in ``fmt`` and write it to a timestamped file.

    Formats: json | markdown/md | html | ndjson (SIEM) | junit (CI).
    """

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fmt = fmt.lower()
    if fmt not in _RENDERERS:
        raise ValueError(f"unknown report format: {fmt!r}")
    renderer, ext = _RENDERERS[fmt]
    content = renderer(report)

    path = out_dir / f"atlas-report-{ts}.{ext}"
    path.write_text(content, encoding="utf-8")
    log.info("wrote %s report to %s", fmt, path)
    return path


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _verdict_badge(v: Verdict) -> str:
    return {"PASS": "✅ PASS", "FAIL": "❌ FAIL", "INCONCLUSIVE": "⚠️ INCONCLUSIVE"}[
        v.value
    ]


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ATLAS-Atomic Report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; margin: 0; padding: 2rem;
         background: #0f1115; color: #e6e6e6; }}
  h1 {{ margin-top: 0; }}
  .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0 2rem; }}
  .card {{ background: #1a1d24; border-radius: 10px; padding: 1rem 1.5rem;
          min-width: 90px; }}
  .card .n {{ font-size: 2rem; font-weight: 700; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
           font-size: 0.75rem; font-weight: 700; margin-right: 0.5rem; }}
  .badge.pass, .card.pass .n {{ color: #4ade80; }}
  .badge.fail, .card.fail .n {{ color: #f87171; }}
  .badge.inconclusive, .card.inconclusive .n {{ color: #fbbf24; }}
  .badge.pass {{ background: rgba(74,222,128,.15); }}
  .badge.fail {{ background: rgba(248,113,113,.15); }}
  .badge.inconclusive {{ background: rgba(251,191,36,.15); }}
  .posture {{ display: inline-block; padding: 0.5rem 1.1rem; border-radius: 8px;
             font-weight: 800; letter-spacing: 0.06em; margin: 0.5rem 0 1rem; }}
  .posture.atrisk {{ background: rgba(248,113,113,.18); color: #f87171; }}
  .posture.needsreview {{ background: rgba(251,191,36,.18); color: #fbbf24; }}
  .posture.incomplete {{ background: rgba(148,163,184,.18); color: #94a3b8; }}
  .posture.secure {{ background: rgba(74,222,128,.18); color: #4ade80; }}
  .sev {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px;
         font-size: 0.68rem; font-weight: 700; margin-right: 0.4rem; }}
  .sev-critical {{ background: #7f1d1d; color: #fecaca; }}
  .sev-high {{ background: #9a3412; color: #fed7aa; }}
  .sev-medium {{ background: #854d0e; color: #fef08a; }}
  .sev-low {{ background: #334155; color: #cbd5e1; }}
  .sev-info {{ background: #1e3a5f; color: #bfdbfe; }}
  details.test {{ background: #1a1d24; border-radius: 10px; margin: 0.6rem 0;
                 padding: 0.8rem 1rem; border-left: 4px solid #333; }}
  details.test.pass {{ border-left-color: #4ade80; }}
  details.test.fail {{ border-left-color: #f87171; }}
  details.test.inconclusive {{ border-left-color: #fbbf24; }}
  summary {{ cursor: pointer; font-size: 1rem; }}
  .meta {{ display: flex; gap: 1rem; flex-wrap: wrap; font-size: 0.8rem;
          color: #9aa0aa; margin: 0.6rem 0; }}
  .reasoning {{ color: #cfd3da; }}
  .msg {{ margin: 0.4rem 0; }}
  .msg .role {{ font-size: 0.7rem; text-transform: uppercase; color: #7c828d;
               letter-spacing: 0.05em; }}
  pre {{ background: #0f1115; padding: 0.6rem 0.8rem; border-radius: 6px;
        overflow-x: auto; white-space: pre-wrap; word-break: break-word; margin: 0.2rem 0; }}
  code {{ color: #93c5fd; }}
</style></head><body>
<h1>ATLAS-Atomic Report</h1>
<div class="posture {posture_class}">RISK POSTURE: {posture}</div>
<p>Author <strong>{author}</strong> · ATLAS-Atomic v{version} · Provider <code>{provider}</code> · Model <code>{model}</code> · {started}</p>
<div class="summary">
  <div class="card"><div class="n">{total}</div>Total</div>
  <div class="card pass"><div class="n">{passed}</div>Pass</div>
  <div class="card fail"><div class="n">{failed}</div>Fail</div>
  <div class="card inconclusive"><div class="n">{inconclusive}</div>Inconclusive</div>
</div>
{rows}
<footer style="margin-top:2rem;color:#7c828d;font-size:0.8rem;border-top:1px solid #2c2c2a;padding-top:1rem;">
  Report by <strong>{author}</strong> · Generated with ATLAS-Atomic v{version}
</footer>
</body></html>"""
