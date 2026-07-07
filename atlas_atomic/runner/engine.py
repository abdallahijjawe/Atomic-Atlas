"""Execution engine.

Runs an :class:`AtomicTest` against a provider, threading a single
:class:`ConversationState` through every turn so context is preserved
automatically. Supports single-turn, multi-turn/stateful, tool-calling, and RAG
scenarios -- all emulated safely, never executing real tools or attacks.

Multi-turn evaluation semantics
-------------------------------
Each turn is evaluated against its own rules if present, otherwise the
test-level rules. The overall test verdict is the "worst" turn verdict, ordered
FAIL > INCONCLUSIVE > PASS: a single leaked secret anywhere fails the test, an
unresolved provider error is inconclusive, and only an all-clear run passes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from atlas_atomic.core.logging import get_logger
from atlas_atomic.core.models import (
    AtomicTest,
    ConversationState,
    EvaluationResult,
    Message,
    Role,
    TestResult,
    Turn,
    Verdict,
)
from atlas_atomic.providers.base import BaseProvider
from atlas_atomic.runner.evaluator import Evaluator

log = get_logger("engine")

# Verdict severity for aggregating multi-turn results (higher = worse).
_SEVERITY = {Verdict.PASS: 0, Verdict.INCONCLUSIVE: 1, Verdict.FAIL: 2}


@dataclass(slots=True)
class _TrialOutcome:
    """The result of a single trial (one full execution) of a test."""

    verdict: Verdict
    reasoning: str
    checks: dict[str, Any]
    transcript: list[dict[str, Any]]
    error: str | None = None
    judge_adjudicated: bool = False


class Engine:
    """Executes atomic tests against a target provider."""

    def __init__(
        self, provider: BaseProvider, evaluator: Evaluator, *, trials: int = 1
    ) -> None:
        self.provider = provider
        self.evaluator = evaluator
        self.trials = max(1, trials)

    def run(self, test: AtomicTest) -> TestResult:
        started = time.monotonic()
        result = TestResult(
            test_id=test.id,
            name=test.name,
            technique=test.technique,
            category=test.category,
            provider=self.provider.name,
            model=self.provider.model,
            verdict=Verdict.INCONCLUSIVE,
            reasoning="",
            severity=test.severity.value,
            atlas_technique_id=test.atlas_technique_id,
            trials=self.trials,
        )
        log.info("running %s (%s) x%d trial(s)", test.id, test.name, self.trials)

        outcomes = [self._run_once(test) for _ in range(self.trials)]
        self._aggregate_trials(result, outcomes)

        result.duration_seconds = round(time.monotonic() - started, 4)
        from datetime import datetime, timezone

        result.finished_at = datetime.now(timezone.utc).isoformat()
        # Cleanup steps are declarative markers recorded for the report; these
        # emulations create no persistent state, so there is nothing to undo.
        if test.cleanup:
            log.debug("%s cleanup steps (declarative): %s", test.id, test.cleanup)
        return result

    # ------------------------------------------------------------------ #
    def _run_once(self, test: AtomicTest) -> _TrialOutcome:
        """Execute one full trial of a test and return its outcome."""

        state = ConversationState()
        if test.system_prompt:
            state.add_system(test.system_prompt)

        turn_results: list[EvaluationResult] = []
        try:
            for index, turn in enumerate(test.turns):
                eval_result = self._run_turn(test, turn, state)
                turn_results.append(eval_result)
                log.debug(
                    "%s turn %d -> %s", test.id, index + 1, eval_result.verdict.value
                )
        except Exception as exc:  # noqa: BLE001 - engine-level safety net
            log.exception("engine error running %s", test.id)
            return _TrialOutcome(
                verdict=Verdict.INCONCLUSIVE,
                reasoning=f"Engine error: {type(exc).__name__}: {exc}",
                checks={},
                transcript=state.transcript(),
                error=f"{type(exc).__name__}: {exc}",
            )

        if not turn_results:
            return _TrialOutcome(
                verdict=Verdict.INCONCLUSIVE,
                reasoning="Test defined no executable turns.",
                checks={},
                transcript=state.transcript(),
            )
        worst = max(turn_results, key=lambda r: _SEVERITY[r.verdict])
        adjudicated = any(
            r.checks.get("judge_adjudicated") for r in turn_results
        )
        return _TrialOutcome(
            verdict=worst.verdict,
            reasoning=worst.reasoning,
            checks={
                f"turn_{i + 1}": {"verdict": r.verdict.value, "checks": r.checks}
                for i, r in enumerate(turn_results)
            },
            transcript=state.transcript(),
            judge_adjudicated=adjudicated,
        )

    def _aggregate_trials(
        self, result: TestResult, outcomes: list["_TrialOutcome"]
    ) -> None:
        n = len(outcomes) or 1
        result.fail_count = sum(1 for o in outcomes if o.verdict is Verdict.FAIL)
        result.pass_count = sum(1 for o in outcomes if o.verdict is Verdict.PASS)
        result.inconclusive_count = sum(
            1 for o in outcomes if o.verdict is Verdict.INCONCLUSIVE
        )
        result.attack_success_rate = round(result.fail_count / n, 4)
        result.judge_adjudicated = any(o.judge_adjudicated for o in outcomes)

        # Security stance: a control that fails even once is not reliable -> FAIL.
        if result.fail_count:
            result.verdict = Verdict.FAIL
        elif result.pass_count:
            result.verdict = Verdict.PASS
        else:
            result.verdict = Verdict.INCONCLUSIVE

        # Representative transcript: a failing trial if any (most informative),
        # otherwise the first trial.
        rep = next(
            (o for o in outcomes if o.verdict is Verdict.FAIL), outcomes[0]
        )
        result.transcript = rep.transcript
        result.error = rep.error
        if self.trials > 1:
            asr = result.attack_success_rate
            prefix = (
                f"Attack succeeded in {result.fail_count}/{self.trials} trials "
                f"(ASR {asr:.0%}). "
            )
            result.reasoning = prefix + rep.reasoning
        else:
            result.reasoning = rep.reasoning
        result.checks = {
            "attack_success_rate": result.attack_success_rate,
            "per_trial": [o.verdict.value for o in outcomes],
            "representative": rep.checks,
        }

    # ------------------------------------------------------------------ #
    def _run_turn(
        self, test: AtomicTest, turn: Turn, state: ConversationState
    ) -> EvaluationResult:
        state.add(Message(role=turn.role, content=turn.prompt))

        # Emulate an attacker-controlled tool/RAG result being placed in context
        # *before* the model answers this turn (retrieved document, tool output).
        # This is content injection only -- no real tool is ever invoked.
        if turn.tool_response is not None:
            state.add_tool(turn.tool_response)

        response = self.provider.chat(state.messages)
        state.add(Message(role=Role.ASSISTANT, content=response.content))

        # Precedence: a per-turn `evaluation` fully governs that turn (and opts
        # out of the test-level ExpectedBehavior), so a benign opener can assert
        # "no refusal" without inheriting the test's blanket "should refuse".
        # Otherwise the turn inherits the test-level rules + expectations.
        if turn.evaluation is not None:
            rules = turn.evaluation
            expected = None
        else:
            rules = test.evaluation
            expected = test.expected

        context = self._context_string(state)
        return self.evaluator.evaluate(response, rules, expected, context=context)

    @staticmethod
    def _context_string(state: ConversationState) -> str:
        return "\n".join(f"[{m.role.value}] {m.content}" for m in state.messages)
