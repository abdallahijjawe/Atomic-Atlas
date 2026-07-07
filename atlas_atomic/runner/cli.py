"""Command-line interface.

Atomic Red Team-style CLI for ATLAS-Atomic. Commands:

    atlas run --test ATLAS-PI-001
    atlas run --technique prompt_injection
    atlas run --all
    atlas list
    atlas validate
    atlas report            # re-render the most recent JSON run as html/md

The CLI is the composition root: it wires config -> provider -> engine ->
evaluator -> reporter. Nothing below this layer knows about argparse.

Exit codes: 0 = all selected tests passed (or nothing to run), 1 = at least one
FAIL, 2 = usage/validation error. INCONCLUSIVE alone does not fail the run.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from atlas_atomic import __author__, __version__
from atlas_atomic.core.config import Config
from atlas_atomic.core.logging import configure_logging, get_logger
from atlas_atomic.core.models import AtomicTest, Verdict, severity_rank
from atlas_atomic.providers import (
    ProviderError,
    available_providers,
    build_provider,
)
from atlas_atomic.runner.engine import Engine
from atlas_atomic.runner.evaluator import Evaluator, LLMJudge
from atlas_atomic.runner.loader import discover_tests, validate_tests
from atlas_atomic.runner.dashboard import write_dashboard
from atlas_atomic.runner.reporter import (
    RunReport,
    _report_from_dict_safe,
    write_report,
)

log = get_logger("cli")

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atlas",
        description="Atomic Red Team-style AI attack emulation for MITRE ATLAS. "
        "Emulates attacker behavior in a safe, controlled environment to "
        "validate AI security controls -- it performs no real attacks.",
    )
    parser.add_argument("--version", action="version", version=f"atlas {__version__}")
    parser.add_argument("--config", help="path to a YAML config file")
    parser.add_argument(
        "--tests-dir", help="override the atomic_tests directory to scan"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable debug logging"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="execute atomic tests")
    sel = p_run.add_mutually_exclusive_group(required=False)
    sel.add_argument("--test", help="run a single test by id (e.g. ATLAS-PI-001)")
    sel.add_argument("--technique", help="run all tests in a technique/category")
    sel.add_argument(
        "--all",
        action="store_true",
        help="run every discovered test (the default when no selector is given)",
    )
    p_run.add_argument(
        "--provider", help="override provider (mock|openai|anthropic|ollama|http)"
    )
    p_run.add_argument("--model", help="override the model id")
    p_run.add_argument(
        "--format",
        action="append",
        choices=["json", "markdown", "md", "html", "ndjson", "junit"],
        help="report format(s) to write; repeatable. json/md/html for humans, "
        "ndjson for SIEM ingestion, junit for CI pipelines.",
    )
    p_run.add_argument("--out", help="report output directory (default: reports/)")
    p_run.add_argument(
        "--trials",
        type=int,
        help="run each test N times and report an attack-success-rate "
        "(models are non-deterministic). Overrides config 'trials'.",
    )
    p_run.add_argument(
        "--fail-on",
        choices=["any", "low", "medium", "high", "critical", "never"],
        default="any",
        help="exit non-zero only when a FAIL at/above this severity occurs "
        "(default: any). Use with CI gating.",
    )
    p_run.add_argument(
        "--baseline",
        help="path to a previous JSON report; flags regressions (was PASS, now FAIL) "
        "and fixes.",
    )
    p_run.add_argument(
        "--mutate",
        action="store_true",
        help="fuzz: also run obfuscated/wrapped variants of each test (base64, "
        "homoglyph, roleplay, ...) to probe guardrail robustness.",
    )
    p_run.add_argument(
        "--mutators",
        help="comma-separated mutators to use with --mutate (default: a built-in "
        "set). See `atlas mutators` for the full list.",
    )

    sub.add_parser("list", help="list discovered atomic tests")
    sub.add_parser("mutators", help="list available attack mutators for --mutate")
    sub.add_parser(
        "doctor",
        help="check your setup: config, target provider, credentials, tests dir",
    )

    p_init = sub.add_parser(
        "init", help="interactively generate a config file for your target"
    )
    p_init.add_argument(
        "--out", default="config/config.yaml", help="where to write the config"
    )

    p_validate = sub.add_parser("validate", help="validate all test YAML files")
    p_validate.add_argument(
        "--strict", action="store_true", help="exit non-zero on any error (default)"
    )

    p_report = sub.add_parser(
        "report", help="re-render a saved JSON report as markdown/html"
    )
    p_report.add_argument("json_report", help="path to a previously saved JSON report")
    p_report.add_argument(
        "--format", choices=["markdown", "md", "html", "ndjson", "junit"], default="html"
    )
    p_report.add_argument("--out", help="output directory (default: reports/)")

    p_dash = sub.add_parser(
        "dashboard",
        help="build an HTML dashboard trending risk posture across saved runs",
    )
    p_dash.add_argument(
        "--reports-dir", help="folder of saved JSON reports (default: reports/)"
    )
    p_dash.add_argument(
        "--out", help="output HTML path (default: <reports-dir>/atlas-dashboard.html)"
    )

    return parser


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #
def _load_config(args: argparse.Namespace) -> Config:
    if args.config and not Path(args.config).exists():
        print(
            f"Warning: --config '{args.config}' not found; "
            "using defaults + environment.",
            file=sys.stderr,
        )
    cfg = Config.load(args.config)
    if args.tests_dir:
        cfg.tests_dir = args.tests_dir
    return cfg


def _select_tests(
    tests: list[AtomicTest], *, test_id: str | None, technique: str | None, all_: bool
) -> list[AtomicTest]:
    if all_:
        return tests
    if test_id:
        return [t for t in tests if t.id == test_id]
    if technique:
        key = technique.lower().replace("-", "_").replace(" ", "_")
        return [
            t
            for t in tests
            if key in (t.category.lower(), t.technique.lower().replace(" ", "_"))
        ]
    return []


def cmd_run(args: argparse.Namespace, cfg: Config) -> int:
    if args.provider:
        cfg.provider.name = args.provider
    if args.model:
        cfg.provider.model = args.model
    if args.trials:
        cfg.trials = max(1, args.trials)

    # Ergonomics: a bare `atlas run` means "run everything".
    if not (args.test or args.technique or args.all):
        args.all = True
        print(
            "No selector given; running all tests "
            "(use --test/--technique to narrow).",
            file=sys.stderr,
        )

    tests = discover_tests(cfg.tests_dir)
    selected = _select_tests(
        tests, test_id=args.test, technique=args.technique, all_=args.all
    )
    if not selected:
        print("No matching tests found.", file=sys.stderr)
        return EXIT_USAGE

    if args.mutate:
        from atlas_atomic.runner.mutations import expand_tests

        names = (
            [m.strip() for m in args.mutators.split(",") if m.strip()]
            if args.mutators
            else None
        )
        try:
            base_n = len(selected)
            selected = expand_tests(selected, names)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        print(f"Fuzzing: expanded {base_n} test(s) -> {len(selected)} with mutations.")

    try:
        provider = build_provider(cfg.provider)
        judge = None
        if cfg.judge.enabled:
            from atlas_atomic.core.config import ProviderConfig

            judge_provider = build_provider(
                ProviderConfig(
                    name=cfg.judge.provider,
                    model=cfg.judge.model,
                    api_key_env=cfg.judge.api_key_env,
                )
            )
            judge = LLMJudge(judge_provider)
    except ProviderError as exc:
        print(f"Provider error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    evaluator = Evaluator(
        judge=judge, adjudicate_ambiguous=cfg.judge.adjudicate_ambiguous
    )
    engine = Engine(provider, evaluator, trials=cfg.trials)
    report = RunReport(provider=provider.name, model=provider.model)

    baseline = _load_baseline(args.baseline) if args.baseline else None

    for test in selected:
        result = engine.run(test)
        report.results.append(result)
        tag = _regression_tag(result, baseline)
        asr = (
            f"  \033[90mASR {result.attack_success_rate:.0%} "
            f"({result.fail_count}/{result.trials})\033[0m"
            if result.trials > 1
            else ""
        )
        adj = "  \033[96m(judge)\033[0m" if result.judge_adjudicated else ""
        print(
            f"{_badge(result.verdict)} {_sev(result.severity)} "
            f"{result.test_id:<16} {result.name}{asr}{adj}{tag}"
        )

    _print_summary(report, baseline)

    for fmt in args.format or []:
        path = write_report(report, args.out or cfg.reports_dir, fmt)
        print(f"  report: {path}")

    return _exit_code(report, args.fail_on)


def _exit_code(report: RunReport, fail_on: str) -> int:
    """Gate the process exit on failures at/above the ``--fail-on`` severity."""

    if fail_on == "never":
        return EXIT_OK
    failed = [r for r in report.results if r.verdict is Verdict.FAIL]
    if not failed:
        return EXIT_OK
    if fail_on == "any":
        return EXIT_FAIL
    threshold = severity_rank(fail_on)
    if any(severity_rank(r.severity) >= threshold for r in failed):
        return EXIT_FAIL
    return EXIT_OK


def cmd_list(cfg: Config) -> int:
    tests = discover_tests(cfg.tests_dir)
    if not tests:
        print(f"No tests found under {cfg.tests_dir}", file=sys.stderr)
        return EXIT_OK
    print(f"{'ID':<18} {'SEVERITY':<10} {'CATEGORY':<22} {'ATLAS':<12} NAME")
    print("-" * 90)
    for t in sorted(tests, key=lambda x: (-severity_rank(x.severity), x.id)):
        atlas_id = t.atlas_technique_id or "-"
        print(
            f"{t.id:<18} {t.severity.value.upper():<10} {t.category:<22} "
            f"{atlas_id:<12} {t.name}"
        )
    print(f"\n{len(tests)} test(s).")
    return EXIT_OK


def cmd_mutators() -> int:
    from atlas_atomic.runner.mutations import MUTATORS

    print(f"{'MUTATOR':<16} DESCRIPTION")
    print("-" * 78)
    for name, m in MUTATORS.items():
        print(f"{name:<16} {m.description}")
    print("\nUse with:  atlas run --all --mutate [--mutators base64,homoglyph,...]")
    return EXIT_OK


_DEFAULT_KEY_ENV = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}


def _mark(ok: bool | None) -> str:
    """Green OK / red X / grey dash for an optional check."""

    if ok is None:
        return "\033[90m-  \033[0m"
    return "\033[92mOK \033[0m" if ok else "\033[91mX  \033[0m"


def _ollama_reachable(base_url: str | None) -> bool:
    import urllib.error
    import urllib.request

    url = (base_url or "http://localhost:11434").rstrip("/") + "/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:  # noqa: S310
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def cmd_doctor(cfg: Config) -> int:
    """Preflight: does the environment look ready to run a real target?

    Prints a short checklist a SOC analyst can scan to see why a run might not
    work, without reading the code -- config source, provider, credentials,
    reachability, and whether the test corpus loads.
    """

    print("ATLAS-Atomic setup check\n")
    print(f"  config       : {cfg.source or '(none -- using defaults + env)'}")
    print(f"  provider     : {cfg.provider.name}")
    print(f"  model        : {cfg.provider.model}")
    print(f"  available    : {', '.join(available_providers())}")
    print()

    ok = True
    name = cfg.provider.name

    # Test corpus loads and validates.
    tests = discover_tests(cfg.tests_dir)
    print(f"  {_mark(bool(tests))} tests dir '{cfg.tests_dir}' -> {len(tests)} test(s)")
    if not tests:
        ok = False
    errors = validate_tests(cfg.tests_dir)
    print(f"  {_mark(not errors)} test YAML valid" + (
        f" ({len(errors)} error(s))" if errors else ""))
    if errors:
        ok = False

    # Reports dir writable.
    writable = _reports_writable(cfg.reports_dir)
    print(f"  {_mark(writable)} reports dir '{cfg.reports_dir}' writable")

    # Provider-specific readiness.
    if name in _DEFAULT_KEY_ENV or cfg.provider.api_key_env:
        env_var = cfg.provider.api_key_env or _DEFAULT_KEY_ENV.get(name, "")
        present = bool(os.environ.get(env_var)) if env_var else False
        print(f"  {_mark(present)} API key: ${env_var or '(unset)'} "
              + ("present" if present else "NOT set"))
        if not present:
            ok = False
            print("       -> a claude.ai/ChatGPT subscription is NOT an API key; "
                  "set the env var to a real API key.")
    elif name == "ollama":
        reachable = _ollama_reachable(cfg.provider.base_url)
        print(f"  {_mark(reachable)} Ollama server "
              f"{cfg.provider.base_url or 'http://localhost:11434'}")
        if not reachable:
            ok = False
            print("       -> start it with `ollama serve` and `ollama pull "
                  f"{cfg.provider.model}`.")
    elif name == "http":
        url = cfg.provider.base_url
        print(f"  {_mark(bool(url))} HTTP endpoint {url or '(base_url not set!)'}")
        if not url:
            ok = False
    elif name == "mock":
        print(f"  {_mark(True)} mock target (offline demo -- no credentials needed)")

    print()
    if ok:
        print("\033[92mReady.\033[0m  Try:  atlas run --all")
        return EXIT_OK
    print("\033[93mSome checks need attention (see above).\033[0m")
    return EXIT_USAGE


def _reports_writable(reports_dir: str) -> bool:
    try:
        p = Path(reports_dir)
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".atlas-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def cmd_validate(cfg: Config) -> int:
    errors = validate_tests(cfg.tests_dir)
    if not errors:
        count = len(discover_tests(cfg.tests_dir))
        print(f"OK: all {count} test file(s) are valid.")
        return EXIT_OK
    print(f"FAILED: {len(errors)} validation error(s):", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    return EXIT_USAGE


def cmd_report(args: argparse.Namespace, cfg: Config) -> int:
    src = Path(args.json_report)
    if not src.exists():
        print(f"No such report: {src}", file=sys.stderr)
        return EXIT_USAGE
    data = json.loads(src.read_text(encoding="utf-8"))
    report = _report_from_dict_safe(data)
    out = write_report(report, args.out or cfg.reports_dir, args.format)
    print(f"Wrote {out}")
    return EXIT_OK


def cmd_dashboard(args: argparse.Namespace, cfg: Config) -> int:
    reports_dir = args.reports_dir or cfg.reports_dir
    out = args.out or str(Path(reports_dir) / "atlas-dashboard.html")
    path = write_dashboard(reports_dir, out)
    print(f"Wrote trend dashboard to {path}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
def _load_baseline(path: str) -> dict[str, str]:
    """Load a prior JSON report into a {test_id: verdict} map for diffing."""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {r["test_id"]: r["verdict"] for r in data.get("results", [])}


def _regression_tag(result, baseline: dict[str, str] | None) -> str:
    """Annotate a result relative to a baseline: regression / fixed / new."""

    if baseline is None:
        return ""
    prev = baseline.get(result.test_id)
    now = result.verdict.value
    if prev is None:
        return "  \033[96m(NEW)\033[0m"
    if prev == "PASS" and now == "FAIL":
        return "  \033[91m(REGRESSION)\033[0m"
    if prev == "FAIL" and now == "PASS":
        return "  \033[92m(FIXED)\033[0m"
    return ""


def _badge(v: Verdict) -> str:
    return {
        "PASS": "\033[92m[PASS]\033[0m",
        "FAIL": "\033[91m[FAIL]\033[0m",
        "INCONCLUSIVE": "\033[93m[INCONCLUSIVE]\033[0m",
    }[v.value]


def _sev(severity: str) -> str:
    color = {
        "critical": "\033[95m",
        "high": "\033[91m",
        "medium": "\033[93m",
        "low": "\033[94m",
        "info": "\033[90m",
    }.get(severity, "\033[0m")
    return f"{color}{severity.upper():<8}\033[0m"


_POSTURE_COLOR = {
    "AT-RISK": "\033[91m",
    "NEEDS-REVIEW": "\033[93m",
    "INCOMPLETE": "\033[90m",
    "SECURE": "\033[92m",
}


def _print_summary(report: RunReport, baseline: dict[str, str] | None = None) -> None:
    s = report.summary
    fbs = report.failures_by_severity
    posture = report.posture
    color = _POSTURE_COLOR.get(posture, "")
    print("-" * 66)
    print(f"RISK POSTURE: {color}{posture}\033[0m")
    print(
        f"Total: {s['total']}  |  PASS: {s['PASS']}  |  "
        f"FAIL: {s['FAIL']}  |  INCONCLUSIVE: {s['INCONCLUSIVE']}"
    )
    if s["FAIL"]:
        print(
            "Failures by severity:  "
            f"CRITICAL {fbs['critical']} | HIGH {fbs['high']} | "
            f"MEDIUM {fbs['medium']} | LOW {fbs['low']}"
        )
    if baseline is not None:
        regressions = [
            r.test_id
            for r in report.results
            if baseline.get(r.test_id) == "PASS" and r.verdict is Verdict.FAIL
        ]
        if regressions:
            print(f"\033[91mREGRESSIONS ({len(regressions)}):\033[0m {', '.join(regressions)}")
        else:
            print("No regressions vs baseline.")


# --------------------------------------------------------------------------- #
# init wizard
# --------------------------------------------------------------------------- #
def cmd_init(args: argparse.Namespace) -> int:
    """Interactive wizard: ask a few questions, write a ready-to-run config.

    Designed so a SOC analyst can connect ATLAS-Atomic to a target in under a
    minute without knowing the config schema or any Python.
    """

    print("ATLAS-Atomic setup - press Enter to accept the [default].\n")
    provider = _ask(
        "Target type: 1) my own chat app (HTTP)  2) OpenAI  3) Anthropic  "
        "4) Ollama  5) offline mock demo",
        "5",
    )
    body: dict[str, Any] = {"tests_dir": "atomic_tests", "reports_dir": "reports"}

    if provider == "1":
        url = _ask("Chat endpoint URL (e.g. https://app.internal/chat)", "")
        pfield = _ask("JSON field the prompt goes in", "message")
        rpath = _ask("JSON path to the reply in the response", "reply")
        auth = _ask("Auth header env var (blank for none, e.g. MY_API_KEY)", "")
        opts: dict[str, Any] = {"prompt_field": pfield, "response_path": rpath}
        p: dict[str, Any] = {"name": "http", "base_url": url, "options": opts}
        if auth:
            p["api_key_env"] = auth
            opts["headers"] = {
                "Authorization": "Bearer {api_key}",
                "Content-Type": "application/json",
            }
        body["provider"] = p
    elif provider == "2":
        body["provider"] = {
            "name": "openai",
            "model": _ask("Model", "gpt-4o-mini"),
            "api_key_env": _ask("API key env var", "OPENAI_API_KEY"),
        }
    elif provider == "3":
        body["provider"] = {
            "name": "anthropic",
            "model": _ask("Model", "claude-opus-4-8"),
            "api_key_env": _ask("API key env var", "ANTHROPIC_API_KEY"),
        }
    elif provider == "4":
        body["provider"] = {
            "name": "ollama",
            "model": _ask("Model", "llama3"),
            "base_url": _ask("Ollama base URL", "http://localhost:11434"),
        }
    else:
        body["provider"] = {"name": "mock", "model": "mock-model"}

    import yaml

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "# Generated by `atlas init`. Edit freely.\n"
        + yaml.safe_dump(body, sort_keys=False),
        encoding="utf-8",
    )
    print(f"\nWrote {out}")
    # Well-known paths are auto-discovered, so the user can skip --config.
    auto = Config.resolve_config_path(None)
    if auto is not None and Path(auto).resolve() == out.resolve():
        print("Next:  atlas doctor            # verify the target is reachable")
        print("       atlas run --format html  # (this config is auto-loaded)")
    else:
        print(f"Next:  atlas --config {out} doctor")
        print(f"       atlas --config {out} run --format html")
    return EXIT_OK


def _ask(prompt: str, default: str) -> str:
    try:
        ans = input(f"{prompt} [{default}]: ").strip()
    except EOFError:
        return default
    return ans or default


# --------------------------------------------------------------------------- #
def _print_banner() -> None:
    """Print the tool banner (with author) to stderr, so stdout stays pipe-safe."""

    line = "=" * 52
    print(
        f"\033[96m{line}\n"
        f"  ATLAS-Atomic v{__version__}  -  MITRE ATLAS attack emulation\n"
        f"  Author: {__author__}\n"
        f"{line}\033[0m",
        file=sys.stderr,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(logging.DEBUG if args.verbose else logging.INFO)
    _print_banner()
    cfg = _load_config(args)
    if cfg.source:
        print(f"\033[90m  config: {cfg.source}\033[0m", file=sys.stderr)

    try:
        if args.command == "run":
            return cmd_run(args, cfg)
        if args.command == "list":
            return cmd_list(cfg)
        if args.command == "mutators":
            return cmd_mutators()
        if args.command == "doctor":
            return cmd_doctor(cfg)
        if args.command == "validate":
            return cmd_validate(cfg)
        if args.command == "report":
            return cmd_report(args, cfg)
        if args.command == "dashboard":
            return cmd_dashboard(args, cfg)
        if args.command == "init":
            return cmd_init(args)
    except KeyboardInterrupt:  # pragma: no cover
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_USAGE
    parser.error(f"unknown command {args.command!r}")
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
