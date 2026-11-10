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

    def rule(self, rule_id: str) -> RuleScore | None:
        """Look up a rule score by Sigma rule id."""
        return next((r for r in self.rules if r.rule_id == rule_id), None)

    def scenario(self, scenario_id: str) -> ScenarioScore | None:
        """Look up a scenario score by id."""
        return next((s for s in self.scenarios if s.scenario_id == scenario_id), None)
