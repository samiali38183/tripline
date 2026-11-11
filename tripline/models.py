"""Typed data models shared across the loader, replay, scorer and reporters.

Scenarios are authored as YAML under ``scenarios/`` and validated into :class:`Scenario` by
:mod:`tripline.scenarios`. Scorecards are produced by :mod:`tripline.scorer` and serialised
to ``scorecard.json``; the heatmap and the PR comment are derived from that file only.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Event = dict[str, Any]
"""A single telemetry record as loaded from NDJSON (Sysmon, auditd or CloudTrail shape)."""

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class Plane(StrEnum):
    """Telemetry plane a scenario executes on."""

    WINDOWS = "windows"
    LINUX = "linux"
    AWS = "aws"


class EmulationKind(StrEnum):
    """How the adversary behaviour is produced."""

    ATOMIC = "atomic"
    """An Atomic Red Team test, referenced by test GUID (runs on a CI runner / lab VM)."""
    SCRIPT = "script"
    """A shell command executed on a lab host or CI runner."""
    REPLAY = "replay"
    """Pre-recorded telemetry (e.g. a Stratus Red Team detonation log) replayed as-is."""


class Provenance(StrEnum):
    """Where a fixture's events came from. Shown verbatim on every scorecard."""

    RECORDED = "recorded"
    """Real telemetry captured from a detonation or a public dataset (source URL required)."""
    SYNTHETIC = "synthetic"
    """Hand-authored events modelled on the real log schema; not captured from a host."""


class ScenarioStatus(StrEnum):
    """Outcome of replaying one scenario."""

    PASSED = "passed"
    """Every expected rule fired on at least one fixture event."""
    FAILED = "failed"
    """At least one expected rule did not fire, is missing, or could not be compiled."""
    PENDING = "pending"
    """The scenario has no committed fixtures yet; it is reported but does not gate."""


class Emulation(BaseModel):
    """Description of the behaviour that produces the scenario's telemetry."""

    model_config = ConfigDict(extra="forbid")

    kind: EmulationKind
    description: str = Field(min_length=1)
    atomic_tests: list[str] = Field(default_factory=list)
    """Atomic Red Team test GUIDs (``kind == atomic``)."""
    command: str | None = None
    """Command line executed on the lab host (``kind == script``) or shown as evidence."""
    source: str | None = None
    """URL of the recorded detonation log or dataset (``kind == replay``)."""

    @model_validator(mode="after")
    def _check_kind_fields(self) -> Emulation:
        if self.kind is EmulationKind.ATOMIC and not self.atomic_tests:
            raise ValueError("atomic emulation requires at least one atomic_tests GUID")
        if self.kind is EmulationKind.REPLAY and not self.source:
            raise ValueError("replay emulation requires a source URL")
        if self.kind is EmulationKind.SCRIPT and not self.command:
            raise ValueError("script emulation requires a command")
        return self


class Fixture(BaseModel):
    """A committed NDJSON telemetry file belonging to a scenario."""

    model_config = ConfigDict(extra="forbid")

    path: Path
    """Relative to the repository root, e.g. ``fixtures/cloud/<scenario>/run.ndjson``."""
    provenance: Provenance
    source: str | None = None
    notes: str | None = None

    @model_validator(mode="after")
    def _recorded_requires_source(self) -> Fixture:
        if self.provenance is Provenance.RECORDED and not self.source:
            raise ValueError("recorded fixtures must cite a source URL")
        return self


class Scenario(BaseModel):
    """One ATT&CK technique-procedure with its emulation, telemetry and expected rules."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
    name: str = Field(min_length=1)
    plane: Plane
    technique: str
    tactic: str = Field(min_length=1)
    weight: int = Field(ge=1, le=10, description="Prevalence weight (Red Canary 2026 rank).")
    emulation: Emulation
    expected_rules: list[str] = Field(min_length=1)
    """Sigma rule UUIDs that must fire on the scenario's fixtures."""
    fixtures: list[Fixture] = Field(default_factory=list)
    """Empty until telemetry has been recorded; the scenario is then reported as *pending*."""
    notes: str | None = None

    @field_validator("technique")
    @classmethod
    def _technique_format(cls, value: str) -> str:
        if not TECHNIQUE_RE.match(value):
            raise ValueError(f"technique must look like T1059 or T1059.001, got {value!r}")
        return value

    @field_validator("expected_rules")
    @classmethod
    def _unique_rules(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("expected_rules contains duplicates")
        return value

    @field_validator("fixtures")
    @classmethod
    def _unique_fixture_paths(cls, value: list[Fixture]) -> list[Fixture]:
        paths = [str(f.path) for f in value]
        if len(set(paths)) != len(paths):
            raise ValueError("fixtures list the same path twice (events would be double counted)")
        return value

    @property
    def parent_technique(self) -> str:
        """``T1059.001`` -> ``T1059``; already-parent IDs are returned unchanged."""
        return self.technique.split(".")[0]


# --------------------------------------------------------------------------- replay models


class RuleOutcome(StrEnum):
    """Why an expected rule did or did not count for a scenario.

    ``NO_APPLICABLE_EVENTS`` is deliberately separate from ``MISSED``: when no fixture event
    matches the rule's logsource, the rule was never run, so ``0 of 0`` says nothing about
    detection quality. It points at a routing problem (wrong rule, wrong fixture, or an event
    shape the logsource router does not recognise).
    """

    MATCHED = "matched"
    """Applicable events existed and the rule matched at least one."""
    MISSED = "missed"
    """Applicable events existed and the rule matched none of them: a detection miss."""
    NO_APPLICABLE_EVENTS = "no_applicable_events"
    """No fixture event matches the rule's logsource: a routing problem, not a miss."""
    ERROR = "error"
    """The rule is missing from the rule set or could not be compiled."""
    PENDING = "pending"
    """The scenario has no fixtures yet."""


def classify_outcome(*, fired: bool, evaluated: int, error: str | None = None) -> RuleOutcome:
    """Derive the outcome of one rule from its counts (pending is decided by the caller)."""
    if error:
        return RuleOutcome.ERROR
    if fired:
        return RuleOutcome.MATCHED
    if evaluated == 0:
        return RuleOutcome.NO_APPLICABLE_EVENTS
    return RuleOutcome.MISSED


def _fill_outcome(data: Any) -> Any:
    """``before`` validator body: derive ``outcome`` when absent (older scorecards, tests)."""
    if isinstance(data, dict) and data.get("outcome") is None:
        derived = classify_outcome(
            fired=bool(data.get("fired")),
            evaluated=int(data.get("evaluated") or 0),
            error=data.get("error"),
        )
        return {**data, "outcome": derived}
    return data


class RuleHit(BaseModel):
    """One expected rule evaluated against one scenario's fixtures."""

    rule_id: str
    title: str | None
    """``None`` when the rule id is not present in the loaded rule set."""
    fired: bool
    hits: int
    """Number of fixture events the rule matched."""
    evaluated: int
    """Number of fixture events whose logsource made the rule applicable."""
    first_match: Event | None = None
    """The first matching event, kept so a failure report can show the evidence."""
    error: str | None = None
    """Why the rule could not be evaluated (missing from the rule set, unsupported...)."""
    outcome: RuleOutcome = RuleOutcome.MISSED
    """Derived from the counts when not given; see :class:`RuleOutcome`."""

    @model_validator(mode="before")
    @classmethod
    def _derive_outcome(cls, data: Any) -> Any:
        return _fill_outcome(data)


class ReplayResult(BaseModel):
    """Outcome of replaying one scenario's fixtures through its expected rules."""

    scenario_id: str
    status: ScenarioStatus
    events: int
    fixtures: list[str]
    rules: list[RuleHit]

    @property
    def missing_rules(self) -> list[str]:
        """Expected rules that did not fire (including rules that could not be evaluated)."""
        return [r.rule_id for r in self.rules if not r.fired]


# --------------------------------------------------------------------------- scoring models


class RuleScore(BaseModel):
    """Coverage of a single Sigma rule across the scenarios that expect it."""

    rule_id: str
    title: str
    level: str | None
    logsource: str
    techniques: list[str]
    expected_scenarios: list[str]
    detected_scenarios: list[str]
    missed_scenarios: list[str]
    pending_scenarios: list[str]
    coverage: float | None
    """Detected / (detected + missed). ``None`` when every expecting scenario is pending."""


class RuleEvidence(BaseModel):
    """Hit counts for one expected rule in one scenario, kept for the HTML report."""

    rule_id: str
    title: str | None
    fired: bool
    hits: int
    evaluated: int
    error: str | None = None
    outcome: RuleOutcome = RuleOutcome.MISSED
    """Added in 0.2.1. Derived from the counts when reading older scorecards."""

    @model_validator(mode="before")
    @classmethod
    def _derive_outcome(cls, data: Any) -> Any:
        return _fill_outcome(data)


class ScenarioScore(BaseModel):
    """Per-scenario view: did every expected rule fire on the committed fixtures?"""

    scenario_id: str
    name: str
    plane: Plane
    technique: str
    tactic: str = ""
    """ATT&CK tactic short name. Empty in scorecards written before 0.2.0."""
    weight: int
    status: ScenarioStatus
    provenance: list[Provenance]
    events: int
    expected_rules: list[str]
    fired_rules: list[str]
    missing_rules: list[str]
    evidence: list[RuleEvidence] = Field(default_factory=list)
    """Per-rule ``hits/evaluated`` counts. Empty in scorecards written before 0.2.0."""

    @model_validator(mode="after")
    def _pending_evidence(self) -> ScenarioScore:
        """A pending scenario's rules were never evaluated; older scorecards lack the outcome."""
        if self.status is ScenarioStatus.PENDING:
            for item in self.evidence:
                item.outcome = RuleOutcome.PENDING
        return self


class TechniqueCoverage(BaseModel):
    """Prevalence-weighted coverage of one technique, the unit the heatmap colours."""

    technique: str
    weight: int
    scenarios: list[str]
    rules: list[str]
    coverage: float
    """Fraction of the technique's scenarios that passed. Pending scenarios count as 0."""
    pending: bool
    """True when no scenario for the technique has fixtures yet."""


class ScorecardTotals(BaseModel):
    """Headline numbers; every figure in the README comes from here."""

    scenarios: int
    passed: int
    failed: int
    pending: int
    rules: int
    weighted_coverage: float
    """sum(weight x coverage) / sum(weight) over every scenario (pending counts as 0)."""
    weighted_coverage_scored: float | None
    """Same, restricted to scenarios that have fixtures. ``None`` if nothing is scored."""


class BenignRuleResult(BaseModel):
    """One rule replayed over the benign corpus."""

    rule_id: str
    title: str
    applicable: int
    """Benign events the rule's logsource applies to. 0 means the rule was not evaluated."""
    matched: int
    """Benign events the rule matched. Every one is a false positive."""
    examples: list[str] = Field(default_factory=list)
    """Up to three matched command lines or paths, so the false positive can be judged."""


class BenignReport(BaseModel):
    """False-positive measurement: every compiled rule replayed over a benign corpus."""

    events: int
    rules: list[BenignRuleResult]

    @property
    def evaluated(self) -> list[BenignRuleResult]:
        """Rules with at least one applicable benign event."""
        return [r for r in self.rules if r.applicable > 0]

    @property
    def firing(self) -> list[BenignRuleResult]:
        """Rules that matched at least one benign event."""
        return [r for r in self.rules if r.matched > 0]

    @property
    def total_matches(self) -> int:
        """Sum of benign events matched, over all rules."""
        return sum(r.matched for r in self.rules)

    def summary(self) -> str:
        """One line for the CLI, the scorecard and the README."""
        return (
            f"{self.total_matches} false-positive matches from {len(self.firing)} of "
            f"{len(self.evaluated)} evaluated rules on {self.events} benign events "
            f"({len(self.rules) - len(self.evaluated)} of {len(self.rules)} rules had no "
            "applicable benign events and were not evaluated)"
        )


class GateResult(BaseModel):
    """Outcome of applying the gate to a scorecard."""

    passed: bool
    failures: list[str]


class Scorecard(BaseModel):
    """Everything the CI gate, the PR comment and the heatmap are derived from."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tripline_version: str
    totals: ScorecardTotals
    rules: list[RuleScore]
    scenarios: list[ScenarioScore]
    techniques: list[TechniqueCoverage]
    gate: GateResult
    benign: BenignReport | None = None
    """Added in 0.3.0: false positives on the benign corpus. ``None`` when no corpus was found."""

    def rule(self, rule_id: str) -> RuleScore | None:
        """Look up a rule score by Sigma rule id."""
        return next((r for r in self.rules if r.rule_id == rule_id), None)

    def scenario(self, scenario_id: str) -> ScenarioScore | None:
        """Look up a scenario score by id."""
        return next((s for s in self.scenarios if s.scenario_id == scenario_id), None)


def describe_outcome(hit: RuleHit | RuleEvidence, events: int) -> str:
    """One-line explanation of a rule result for the CLI and the HTML report.

    ``events`` is the number of fixture events of the scenario; it is only used to make the
    routing-problem message concrete.
    """
    outcome = hit.outcome
    if outcome is RuleOutcome.ERROR:
        return hit.error or "rule could not be evaluated"
    if outcome is RuleOutcome.PENDING:
        return "no fixtures"
    if outcome is RuleOutcome.NO_APPLICABLE_EVENTS:
        return (
            f"no applicable events: 0 of {events} fixture events match the rule's logsource "
            "(routing problem, not a detection miss)"
        )
    counts = f"{hit.hits}/{hit.evaluated} applicable events"
    return counts + (" (rule did not match)" if outcome is RuleOutcome.MISSED else "")
