"""Trend dashboard.

Reads a folder of saved JSON run reports and renders a single self-contained
HTML page that trends **risk posture** and control health over time -- the view a
SOC lead wants for "are our AI defenses getting better or worse?".

Charts (pure inline SVG, no JS, no external assets -- CSP-safe and offline):

* **Pass rate over runs** -- a single-series line (change over time); the title
  names the series, so no legend box is needed.
* **Failures by severity over runs** -- stacked bars using the validated status
  palette (critical/high/medium/low), always shipped with a legend + a table view
  so severity is never conveyed by color alone.
* **Posture timeline** -- one labeled status chip per run.
* **Runs table** -- the accessible, exact-values fallback for every data point.

Colors follow the dataviz status palette (validated to clear 3:1 contrast on the
dark chart surface #1a1a19); severity is an ordered status ramp, not arbitrary
categorical hues.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from atlas_atomic import __author__, __version__
from atlas_atomic.core.logging import get_logger
from atlas_atomic.runner.reporter import RunReport, _report_from_dict_safe

log = get_logger("dashboard")

# --- palette (dataviz status palette; validated on dark surface #1a1a19) ----- #
_SURFACE = "#1a1a19"
_PAGE = "#0d0d0d"
_INK = "#ffffff"
_INK2 = "#c3c2b7"
_MUTED = "#898781"
_GRID = "#2c2c2a"
_LINE = "#0ca30c"  # good/green: higher pass rate = better

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]
_SEVERITY_COLOR = {
    "critical": "#d03b3b",
    "high": "#ec835a",
    "medium": "#fab219",
    "low": "#6b7280",
}
_POSTURE_COLOR = {
    "SECURE": "#0ca30c",
    "NEEDS-REVIEW": "#fab219",
    "AT-RISK": "#d03b3b",
    "INCOMPLETE": "#898781",
}


@dataclass(slots=True)
class RunPoint:
    """One run distilled to the numbers the dashboard trends."""

    timestamp: str
    label: str
    posture: str
    total: int
    passed: int
    failed: int
    inconclusive: int
    provider: str
    model: str
    severity_fails: dict[str, int] = field(default_factory=dict)

    @property
    def pass_rate(self) -> float:
        return (self.passed / self.total * 100.0) if self.total else 0.0


# --------------------------------------------------------------------------- #
def load_run_points(reports_dir: str | Path) -> list[RunPoint]:
    """Load every JSON report under ``reports_dir`` into time-ordered points.

    Files that are not ATLAS-Atomic run reports (or fail to parse) are skipped,
    so the reports folder can safely also hold ndjson/xml/html artifacts.
    """

    points: list[RunPoint] = []
    for path in Path(reports_dir).glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict) or "results" not in data or "summary" not in data:
            continue
        report = _report_from_dict_safe(data)
        points.append(_to_point(report, fallback=path.stem))
    points.sort(key=lambda p: p.timestamp)
    return points


def _to_point(report: RunReport, fallback: str) -> RunPoint:
    s = report.summary
    ts = report.started_at or fallback
    return RunPoint(
        timestamp=ts,
        label=_short_time(ts),
        posture=report.posture,
        total=s["total"],
        passed=s["PASS"],
        failed=s["FAIL"],
        inconclusive=s["INCONCLUSIVE"],
        provider=report.provider,
        model=report.model,
        severity_fails=report.failures_by_severity,
    )


def _short_time(ts: str) -> str:
    for fmt in ("iso", "compact"):
        try:
            if fmt == "iso":
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            else:
                dt = datetime.strptime(ts[:15], "%Y%m%dT%H%M%S")
            return dt.strftime("%m-%d %H:%M")
        except (ValueError, TypeError):
            continue
    return ts[:16]


# --------------------------------------------------------------------------- #
# SVG geometry helpers
# --------------------------------------------------------------------------- #
_W, _H = 720, 260
_PAD_L, _PAD_R, _PAD_T, _PAD_B = 46, 18, 18, 34


def _x(i: int, n: int) -> float:
    if n <= 1:
        return (_PAD_L + (_W - _PAD_R)) / 2
    span = _W - _PAD_L - _PAD_R
    return _PAD_L + span * i / (n - 1)


def _bar_x(i: int, n: int) -> tuple[float, float]:
    span = _W - _PAD_L - _PAD_R
    slot = span / max(n, 1)
    width = min(slot * 0.62, 46)
    cx = _PAD_L + slot * (i + 0.5)
    return cx - width / 2, width


def _y(value: float, vmax: float) -> float:
    plot_h = _H - _PAD_T - _PAD_B
    vmax = vmax or 1
    return _PAD_T + plot_h * (1 - value / vmax)


def _line_chart(points: list[RunPoint]) -> str:
    n = len(points)
    coords = [(_x(i, n), _y(p.pass_rate, 100)) for i, p in enumerate(points)]
    grid = []
    for gv in (0, 25, 50, 75, 100):
        gy = _y(gv, 100)
        grid.append(
            f'<line x1="{_PAD_L}" y1="{gy:.1f}" x2="{_W - _PAD_R}" y2="{gy:.1f}" '
            f'stroke="{_GRID}" stroke-width="1"/>'
            f'<text x="{_PAD_L - 8}" y="{gy + 4:.1f}" text-anchor="end" '
            f'fill="{_MUTED}" font-size="11">{gv}%</text>'
        )
    poly = " ".join(f"{cx:.1f},{cy:.1f}" for cx, cy in coords)
    dots = []
    for (cx, cy), p in zip(coords, points):
        dots.append(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="4.5" fill="{_LINE}" '
            f'stroke="{_SURFACE}" stroke-width="2">'
            f"<title>{html.escape(p.label)} — {p.pass_rate:.0f}% pass "
            f"({p.passed}/{p.total})</title></circle>"
        )
    # Direct-label the most recent point only (no number on every point).
    last_label = ""
    if coords:
        cx, cy = coords[-1]
        last_label = (
            f'<text x="{cx - 8:.1f}" y="{cy - 10:.1f}" text-anchor="end" '
            f'fill="{_INK}" font-size="12" font-weight="700">'
            f"{points[-1].pass_rate:.0f}%</text>"
        )
    xlabels = _x_labels(points, n)
    line = (
        f'<polyline points="{poly}" fill="none" stroke="{_LINE}" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
        if len(coords) > 1
        else ""
    )
    return _svg(
        "Pass rate over runs (higher is better)",
        "".join(grid) + line + "".join(dots) + last_label + xlabels,
    )


def _stacked_chart(points: list[RunPoint]) -> str:
    n = len(points)
    max_fail = max((p.failed for p in points), default=0) or 1
    grid = []
    steps = _nice_ticks(max_fail)
    for gv in steps:
        gy = _y(gv, steps[-1])
        grid.append(
            f'<line x1="{_PAD_L}" y1="{gy:.1f}" x2="{_W - _PAD_R}" y2="{gy:.1f}" '
            f'stroke="{_GRID}" stroke-width="1"/>'
            f'<text x="{_PAD_L - 8}" y="{gy + 4:.1f}" text-anchor="end" '
            f'fill="{_MUTED}" font-size="11">{gv}</text>'
        )
    bars = []
    scale_max = steps[-1]
    for i, p in enumerate(points):
        bx, bw = _bar_x(i, n)
        base = _H - _PAD_B
        # Stack low (bottom) -> critical (top); 2px surface gap between segments.
        for sev in reversed(_SEVERITY_ORDER):
            count = p.severity_fails.get(sev, 0)
            if count <= 0:
                continue
            seg_h = (count / scale_max) * (_H - _PAD_T - _PAD_B)
            top = base - seg_h
            bars.append(
                f'<rect x="{bx:.1f}" y="{top:.1f}" width="{bw:.1f}" '
                f'height="{max(seg_h - 2, 0):.1f}" rx="2" '
                f'fill="{_SEVERITY_COLOR[sev]}">'
                f"<title>{html.escape(p.label)} — {sev}: {count}</title></rect>"
            )
            base = top
    xlabels = _x_labels(points, n)
    return _svg(
        "Failures by severity over runs (lower is better)",
        "".join(grid) + "".join(bars) + xlabels,
    )


def _x_labels(points: list[RunPoint], n: int) -> str:
    if n == 0:
        return ""
    every = max(1, n // 8)
    out = []
    for i, p in enumerate(points):
        if i % every and i != n - 1:
            continue
        cx = _x(i, n)
        # Anchor first/last labels inward so they never overflow the viewBox edge.
        if i == 0:
            anchor = "start"
        elif i == n - 1:
            anchor = "end"
        else:
            anchor = "middle"
        out.append(
            f'<text x="{cx:.1f}" y="{_H - 12}" text-anchor="{anchor}" '
            f'fill="{_MUTED}" font-size="10">{html.escape(p.label)}</text>'
        )
    return "".join(out)


def _nice_ticks(vmax: int) -> list[int]:
    if vmax <= 4:
        return list(range(0, vmax + 1))
    step = max(1, round(vmax / 4))
    ticks = list(range(0, vmax + step, step))
    return ticks or [0, vmax]


def _svg(title: str, inner: str) -> str:
    return (
        f'<figure class="chart"><figcaption>{html.escape(title)}</figcaption>'
        f'<svg viewBox="0 0 {_W} {_H}" preserveAspectRatio="xMidYMid meet" '
        f'role="img" aria-label="{html.escape(title)}">{inner}</svg></figure>'
    )


# --------------------------------------------------------------------------- #
def render_dashboard(points: list[RunPoint]) -> str:
    if not points:
        empty = (
            '<p class="empty">No run reports found. Run '
            "<code>atlas run --all --format json</code> first.</p>"
        )
        headline = legend = charts = timeline = table = ""
    else:
        headline = _headline(points)
        legend = _legend()
        charts = f'<div class="charts">{_line_chart(points)}{_stacked_chart(points)}</div>'
        timeline = _timeline(points)
        table = _table(points)
        empty = ""
    generated = html.escape(datetime.now().strftime("%Y-%m-%d %H:%M"))
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>ATLAS-Atomic Trend Dashboard</title>\n"
        f"<style>{_css()}</style></head><body>\n"
        "<h1>ATLAS-Atomic — AI Security Trend</h1>\n"
        f'<div class="meta">By <strong>{html.escape(__author__)}</strong> · '
        f"ATLAS-Atomic v{html.escape(__version__)} · "
        f"Generated {generated} · {len(points)} run(s)</div>\n"
        f"{headline}\n{legend}\n{charts}\n{timeline}\n{table}\n{empty}\n"
        f'<footer style="margin-top:2rem;color:{_MUTED};font-size:0.8rem;">'
        f"Dashboard by {html.escape(__author__)} · ATLAS-Atomic v{html.escape(__version__)}"
        "</footer>\n"
        "</body></html>"
    )


def _headline(points: list[RunPoint]) -> str:
    latest = points[-1]
    color = _POSTURE_COLOR.get(latest.posture, _MUTED)
    delta = ""
    if len(points) > 1:
        prev = points[-2]
        d = latest.pass_rate - prev.pass_rate
        arrow = "▲" if d > 0 else ("▼" if d < 0 else "▬")
        dcolor = _LINE if d > 0 else (_SEVERITY_COLOR["critical"] if d < 0 else _MUTED)
        delta = (
            f'<span class="delta" style="color:{dcolor}">{arrow} '
            f"{abs(d):.0f}% vs previous</span>"
        )
    return (
        f'<div class="headline">'
        f'<div class="posture-chip" style="background:{color}">'
        f"{html.escape(latest.posture)}</div>"
        f'<div class="hstat"><span class="n">{latest.pass_rate:.0f}%</span>'
        f"<span class=\"l\">pass rate</span></div>"
        f'<div class="hstat"><span class="n">{latest.failed}</span>'
        f"<span class=\"l\">failing controls</span></div>"
        f'<div class="hstat"><span class="n">{latest.total}</span>'
        f"<span class=\"l\">controls tested</span></div>"
        f"{delta}</div>"
        f'<p class="sub">Latest run: {html.escape(latest.label)} · '
        f"{html.escape(latest.provider)} / {html.escape(latest.model)}</p>"
    )


def _legend() -> str:
    items = "".join(
        f'<span class="lg"><span class="sw" style="background:'
        f'{_SEVERITY_COLOR[s]}"></span>{s}</span>'
        for s in _SEVERITY_ORDER
    )
    return f'<div class="legend">Severity: {items}</div>'


def _timeline(points: list[RunPoint]) -> str:
    chips = "".join(
        f'<span class="tl" style="background:{_POSTURE_COLOR.get(p.posture, _MUTED)}" '
        f'title="{html.escape(p.label)}: {html.escape(p.posture)}">'
        f"{html.escape(p.posture)}</span>"
        for p in points
    )
    return f'<h2>Posture timeline</h2><div class="timeline">{chips}</div>'


def _table(points: list[RunPoint]) -> str:
    rows = []
    for p in reversed(points):  # newest first
        color = _POSTURE_COLOR.get(p.posture, _MUTED)
        sev = p.severity_fails
        rows.append(
            f"<tr><td>{html.escape(p.label)}</td>"
            f'<td><span class="dot" style="background:{color}"></span>'
            f"{html.escape(p.posture)}</td>"
            f"<td>{p.pass_rate:.0f}%</td><td>{p.passed}</td><td>{p.failed}</td>"
            f"<td>{p.inconclusive}</td>"
            f"<td>{sev.get('critical', 0)}</td><td>{sev.get('high', 0)}</td>"
            f"<td>{sev.get('medium', 0)}</td><td>{sev.get('low', 0)}</td></tr>"
        )
    return (
        "<h2>All runs</h2><div class=\"tablewrap\"><table><thead><tr>"
        "<th>Run</th><th>Posture</th><th>Pass&nbsp;%</th><th>Pass</th>"
        "<th>Fail</th><th>Inconcl.</th><th>Crit</th><th>High</th>"
        "<th>Med</th><th>Low</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


# CSS kept as a plain string (literal braces); palette values injected by token
# replacement so there is no brace-escaping / double-format hazard.
_CSS = """
  body { font-family: system-ui, sans-serif; margin: 0; padding: 2rem;
         background: __PAGE__; color: __INK__; }
  h1 { margin: 0 0 0.2rem; }
  h2 { margin: 2rem 0 0.6rem; font-size: 1.05rem; color: __INK2__; }
  .meta { color: __MUTED__; font-size: 0.85rem; margin-bottom: 1.5rem; }
  .headline { display: flex; gap: 1.4rem; align-items: center; flex-wrap: wrap;
              background: __SURFACE__; padding: 1.1rem 1.4rem; border-radius: 12px; }
  .posture-chip { padding: 0.5rem 1rem; border-radius: 8px; font-weight: 800;
                  letter-spacing: 0.05em; color: #0d0d0d; }
  .hstat { display: flex; flex-direction: column; }
  .hstat .n { font-size: 1.8rem; font-weight: 700; }
  .hstat .l { font-size: 0.75rem; color: __MUTED__; text-transform: uppercase;
              letter-spacing: 0.04em; }
  .delta { font-weight: 700; font-size: 0.9rem; margin-left: auto; }
  .sub { color: __MUTED__; font-size: 0.85rem; margin: 0.6rem 0 0; }
  .legend { margin: 1.4rem 0 0.2rem; color: __INK2__; font-size: 0.85rem; }
  .lg { margin-right: 1rem; }
  .sw { display: inline-block; width: 11px; height: 11px; border-radius: 3px;
        margin-right: 0.35rem; vertical-align: -1px; }
  .charts { display: grid; grid-template-columns: 1fr; gap: 1rem; }
  @media (min-width: 900px) { .charts { grid-template-columns: 1fr 1fr; } }
  .chart { background: __SURFACE__; border-radius: 12px; padding: 1rem 1.1rem;
           margin: 0; overflow-x: auto; }
  .chart figcaption { font-size: 0.9rem; color: __INK2__; margin-bottom: 0.4rem; }
  .chart svg { width: 100%; height: auto; }
  .timeline { display: flex; gap: 4px; flex-wrap: wrap; }
  .tl { font-size: 0.62rem; font-weight: 700; color: #0d0d0d; padding: 0.25rem 0.4rem;
        border-radius: 4px; }
  .tablewrap { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
  th, td { text-align: right; padding: 0.4rem 0.7rem; border-bottom: 1px solid __GRID__; }
  th:first-child, td:first-child, th:nth-child(2), td:nth-child(2) { text-align: left; }
  thead th { color: __MUTED__; font-weight: 600; }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%;
         margin-right: 0.4rem; }
  .empty { color: __MUTED__; }
  code { color: #93c5fd; }
"""


def _css() -> str:
    return (
        _CSS.replace("__PAGE__", _PAGE)
        .replace("__SURFACE__", _SURFACE)
        .replace("__INK2__", _INK2)
        .replace("__INK__", _INK)
        .replace("__MUTED__", _MUTED)
        .replace("__GRID__", _GRID)
    )


def write_dashboard(reports_dir: str | Path, out_path: str | Path) -> Path:
    """Build the trend dashboard from ``reports_dir`` and write it to ``out_path``."""

    points = load_run_points(reports_dir)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_dashboard(points), encoding="utf-8")
    log.info("wrote trend dashboard (%d run(s)) to %s", len(points), out)
    return out
