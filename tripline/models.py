"""Typed data models shared across the planner, scorer and reporters.

Scenarios are authored as YAML under ``scenarios/`` and validated into :class:`Scenario`.
Scorecards are produced by :mod:`tripline.scorer` and serialised to ``scorecard.json``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
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
    """Real telemetry captured from a detonation (source URL required)."""
    SYNTHETIC = "synthetic"
    """Hand-authored events modelled on the real log schema; not captured from a host."""


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
    """URL of the recorded detonation log (``kind == replay``)."""

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
    fixtures: list[Fixture] = Field(min_length=1)
    mutations: list[str] | None = None
    """Restrict robustness testing to these mutation names; ``None`` = all applicable."""

    @field_validator("technique")
    @classmethod
    def _technique_format(cls, value: str) -> str:
        if not TECHNIQUE_RE.match(value):
            raise ValueError(f"technique must look like T1059 or T1059.001, got {value!r}")
        return value

    @property
    def parent_technique(self) -> str:
        """``T1059.001`` -> ``T1059``; already-parent IDs are returned unchanged."""
        return self.technique.split(".")[0]

    @classmethod
    def from_yaml(cls, path: Path) -> Scenario:
        """Load and validate a scenario file."""
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return cls.model_validate(data)


def load_scenarios(directory: Path) -> list[Scenario]:
    """Load every ``*.yaml`` scenario in ``directory``, sorted by id, rejecting duplicates."""
    scenarios = [Scenario.from_yaml(p) for p in sorted(directory.glob("*.yaml"))]
    seen: set[str] = set()
    for scenario in scenarios:
        if scenario.id in seen:
            raise ValueError(f"duplicate scenario id {scenario.id!r}")
        seen.add(scenario.id)
    return sorted(scenarios, key=lambda s: s.id)


# --------------------------------------------------------------------------- scoring models


class Thresholds(BaseModel):
    """Minimum acceptable scores. A rule below any ``*_min`` fails the gate."""

    model_config = ConfigDict(extra="forbid")

    coverage_min: float = Field(default=1.0, ge=0.0, le=1.0)
    precision_min: float = Field(default=0.95, ge=0.0, le=1.0)
    robustness_min: float = Field(default=0.75, ge=0.0, le=1.0)
    robustness_is_blocking: bool = False
    """Robustness failures are reported as warnings unless this is true."""
    regression_tolerance: float = Field(default=1e-9, ge=0.0)
    """A metric may drop by at most this much relative to the baseline scorecard."""


class MutationOutcome(BaseModel):
    """Result of replaying one mutated scenario fixture through one rule."""

    scenario_id: str
    mutation: str
    detected: bool


class FalsePositiveExample(BaseModel):
    """A benign event a rule matched, with the fields the analyst should look at first."""

    corpus: str
    excerpt: dict[str, Any]


class RuleScore(BaseModel):
    """Four-axis score for a single Sigma rule."""

    rule_id: str
    title: str
    level: str | None
    logsource: str
    techniques: list[str]
    expected_scenarios: list[str]
    detected_scenarios: list[str]
    missed_scenarios: list[str]
    coverage: float | None
    """Fraction of expected scenarios where the rule fired (``None`` if none expected)."""
    true_positives: int
    false_positives: int
    precision: float | None
    """``TP / (TP + FP)`` over attack fixtures plus benign corpora (``None`` if no hits)."""
    fp_examples: list[FalsePositiveExample]
    mutations: list[MutationOutcome]
    robustness: float | None
    """Fraction of applicable mutations still detected (``None`` if nothing to mutate)."""
    evaded_by: list[str]
    events_scanned: int
    events_per_hit: float | None
    eval_us_per_event: float
    """Mean wall-clock microseconds the pure-Python predicate spent per evaluated event."""


class ScenarioScore(BaseModel):
    """Per-scenario view: did every expected rule fire on the committed fixture?"""

    scenario_id: str
    name: str
    plane: Plane
    technique: str
    weight: int
    provenance: list[Provenance]
    events: int
    expected_rules: list[str]
    fired_rules: list[str]
    missing_rules: list[str]
    unexpected_rules: list[str]
    passed: bool


class TechniqueCoverage(BaseModel):
    """Prevalence-weighted coverage of one technique for the Navigator heatmap."""

    technique: str
    weight: int
    scenarios: list[str]
    rules: list[str]
    coverage: float
    robust_coverage: float
    """``coverage * mean(robustness)`` - what the heatmap colours by."""


class CorpusSummary(BaseModel):
    """Size and provenance of a benign corpus used for precision."""

    name: str
    plane: Plane
    events: int
    provenance: Provenance
    source: str | None


class GateResult(BaseModel):
    """Outcome of applying thresholds (and an optional baseline) to a scorecard."""

    passed: bool
    failures: list[str]
    warnings: list[str]


class Scorecard(BaseModel):
    """Everything the CI gate, the PR comment and the heatmap are derived from."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tripline_version: str
    thresholds: Thresholds
    rules: list[RuleScore]
    scenarios: list[ScenarioScore]
    techniques: list[TechniqueCoverage]
    corpora: list[CorpusSummary]
    gate: GateResult

    def rule(self, rule_id: str) -> RuleScore | None:
        """Look up a rule score by Sigma rule id."""
        return next((r for r in self.rules if r.rule_id == rule_id), None)
