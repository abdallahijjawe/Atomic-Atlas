"""Core domain models for ATLAS-Atomic.

These are plain ``dataclasses`` (no third-party dependency) so the domain layer
stays framework-agnostic. Parsing/validation of external YAML happens in
``runner.loader``; these types represent already-validated, in-memory state.

The model hierarchy:

    AtomicTest            -- a single test definition loaded from YAML
      Turn[]              -- ordered conversation turns (single- or multi-turn)
      ExpectedBehavior    -- what the *defender* should do (e.g. refuse)
      EvaluationRules     -- how we decide PASS/FAIL from the response

    ConversationState     -- runtime state accumulated while executing a test
      Message[]           -- the running transcript

    TestResult            -- the outcome of executing one AtomicTest
      EvaluationResult    -- verdict + reasoning for each turn / overall
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Role(str, enum.Enum):
    """Chat roles, aligned with the common OpenAI/Anthropic message schema."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class Severity(str, enum.Enum):
    """Risk severity of a control failure, for SOC triage and prioritization.

    Ordered low-to-high; use :func:`severity_rank` to compare. A test's severity
    describes how damaging it is if the *defense fails* (e.g. leaking a secret is
    HIGH, issuing a destructive command is CRITICAL).
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(severity: "Severity | str") -> int:
    """Return the numeric rank of a severity (higher = more severe)."""

    if isinstance(severity, str):
        severity = Severity(severity)
    return _SEVERITY_RANK[severity]


class Verdict(str, enum.Enum):
    """The three-valued outcome of a test, matching Atomic Red Team semantics.

    PASS         -- the defensive control behaved as expected (attack emulation
                    was correctly handled/blocked).
    FAIL         -- the control did NOT behave as expected (potential exposure).
    INCONCLUSIVE -- the framework could not determine an outcome (e.g. provider
                    error, ambiguous response, judge unavailable).
    """

    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


# --------------------------------------------------------------------------- #
# Conversation primitives
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Message:
    """A single message in a conversation transcript."""

    role: Role
    content: str
    # Optional tool-call metadata for tool-calling conversations.
    name: str | None = None
    tool_call_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"role": self.role.value, "content": self.content}
        if self.name is not None:
            data["name"] = self.name
        if self.tool_call_id is not None:
            data["tool_call_id"] = self.tool_call_id
        if self.metadata:
            data["metadata"] = self.metadata
        return data


@dataclass(slots=True)
class ProviderResponse:
    """Normalized response returned by any provider."""

    content: str
    model: str
    raw: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    # Populated when the provider call itself failed; verdict becomes INCONCLUSIVE.
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(slots=True)
class Turn:
    """A single step of an atomic test's attack script.

    A test with one turn is "single-turn"; multiple turns model a multi-turn
    jailbreak / stateful conversation. ``tool_response`` lets a test simulate the
    result a tool would return (for tool-misuse and RAG scenarios) without ever
    executing a real tool.
    """

    prompt: str
    role: Role = Role.USER
    # Simulated tool output injected back into the conversation after this turn,
    # e.g. a poisoned RAG document or a malicious tool result. Purely emulated.
    tool_response: str | None = None
    # Per-turn evaluation override; if None the test-level rules apply.
    evaluation: EvaluationRules | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ConversationState:
    """Mutable runtime state accumulated while executing a test.

    The engine threads a single ``ConversationState`` through all turns so that
    context is preserved automatically for multi-turn/stateful tests.
    """

    messages: list[Message] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)

    def add(self, message: Message) -> None:
        self.messages.append(message)

    def add_user(self, content: str) -> None:
        self.add(Message(role=Role.USER, content=content))

    def add_assistant(self, content: str) -> None:
        self.add(Message(role=Role.ASSISTANT, content=content))

    def add_system(self, content: str) -> None:
        self.add(Message(role=Role.SYSTEM, content=content))

    def add_tool(self, content: str, name: str | None = None) -> None:
        self.add(Message(role=Role.TOOL, content=content, name=name))

    def transcript(self) -> list[dict[str, Any]]:
        return [m.to_dict() for m in self.messages]


# --------------------------------------------------------------------------- #
# Test definition
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ExpectedBehavior:
    """What a *correctly defended* target should do when facing the attack.

    ``should_refuse`` is the most common expectation: a robust control refuses
    the malicious request. ``should_not_contain`` lists strings that must never
    appear (e.g. a secret canary planted in the system prompt).
    """

    should_refuse: bool = False
    should_not_contain: list[str] = field(default_factory=list)
    should_contain: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass(slots=True)
class EvaluationRules:
    """Declarative rules that map a response to a verdict.

    Multiple rule families can be combined; see ``runner.evaluator`` for the
    precedence and combination semantics. Every field is optional so a test only
    specifies what it needs.
    """

    # Substring/keyword matching (case-insensitive by default).
    contains_any: list[str] = field(default_factory=list)
    contains_all: list[str] = field(default_factory=list)
    not_contains: list[str] = field(default_factory=list)
    # Regular-expression matching.
    regex_any: list[str] = field(default_factory=list)
    regex_all: list[str] = field(default_factory=list)
    # Exact string match of the (stripped) response.
    exact_match: str | None = None
    # JSON-schema validation of a response expected to be JSON.
    json_schema: dict[str, Any] | None = None
    # Built-in refusal detector.
    refusal_expected: bool | None = None
    # LLM-as-a-judge rubric (optional; requires a judge provider).
    llm_judge: str | None = None
    # When True (default), string/keyword comparisons ignore case.
    case_insensitive: bool = True

    def is_empty(self) -> bool:
        return not any(
            [
                self.contains_any,
                self.contains_all,
                self.not_contains,
                self.regex_any,
                self.regex_all,
                self.exact_match is not None,
                self.json_schema is not None,
                self.refusal_expected is not None,
                self.llm_judge is not None,
            ]
        )


@dataclass(slots=True)
class AtomicTest:
    """A single, independent atomic test loaded from a YAML file."""

    id: str
    name: str
    technique: str
    turns: list[Turn]
    description: str = ""
    category: str = "uncategorized"
    severity: Severity = Severity.MEDIUM
    atlas_technique_id: str = ""  # e.g. "AML.T0051" (MITRE ATLAS technique id)
    prerequisites: list[str] = field(default_factory=list)
    system_prompt: str | None = None
    expected: ExpectedBehavior = field(default_factory=ExpectedBehavior)
    evaluation: EvaluationRules = field(default_factory=EvaluationRules)
    cleanup: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # Absolute path the test was loaded from (populated by the loader).
    source_path: str | None = None

    @property
    def is_multi_turn(self) -> bool:
        return len(self.turns) > 1


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class EvaluationResult:
    """The verdict for a single evaluation together with human-readable reasoning."""

    verdict: Verdict
    reasoning: str
    # Per-rule breakdown, e.g. {"refusal_expected": True, "contains_any": False}.
    checks: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TestResult:
    """The full outcome of executing one ``AtomicTest``."""

    __test__ = False  # not a pytest test class despite the 'Test' prefix

    test_id: str
    name: str
    technique: str
    category: str
    provider: str
    model: str
    verdict: Verdict
    reasoning: str
    severity: str = Severity.MEDIUM.value
    atlas_technique_id: str = ""
    # Multi-trial aggregation (defaults describe a single-trial run).
    trials: int = 1
    pass_count: int = 1
    fail_count: int = 0
    inconclusive_count: int = 0
    attack_success_rate: float = 0.0  # fraction of trials where the attack got through
    judge_adjudicated: bool = False
    transcript: list[dict[str, Any]] = field(default_factory=list)
    checks: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str | None = None
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "name": self.name,
            "technique": self.technique,
            "category": self.category,
            "severity": self.severity,
            "atlas_technique_id": self.atlas_technique_id,
            "provider": self.provider,
            "model": self.model,
            "verdict": self.verdict.value,
            "reasoning": self.reasoning,
            "trials": self.trials,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "inconclusive_count": self.inconclusive_count,
            "attack_success_rate": self.attack_success_rate,
            "judge_adjudicated": self.judge_adjudicated,
            "transcript": self.transcript,
            "checks": self.checks,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
        }
