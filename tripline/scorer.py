"""Turn replay results into a scorecard, a JUnit report and a gate verdict.

Coverage is computed three ways, each answering a different question:

* **per rule** - of the scenarios that expect this rule, how many did it fire on?
* **per scenario** - did *every* expected rule fire? (the unit the CI gate fails on)
* **per technique, prevalence-weighted** - sum(weight x coverage) / sum(weight), where the
  weight is the Red Canary Threat Detection Report rank. This is the number the heatmap
  colours and the one that answers "how exposed are we to what actually happens".

Pending scenarios (no fixtures yet) count as zero coverage in the headline figure and are
listed separately, so the README can never quietly inflate the number.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from xml.etree import ElementTree as ET

from tripline import __version__
from tripline.engine.compiler import CompiledRule
from tripline.engine.rules import RuleSet
from tripline.events import write_text_lf
from tripline.models import (
    BenignReport,
    GateResult,
    ReplayResult,
    RobustnessReport,
    RuleEvidence,
    RuleOutcome,
    RuleScore,
    Scenario,
    ScenarioScore,
    ScenarioStatus,
    Scorecard,
    ScorecardTotals,
    TechniqueCoverage,
    describe_outcome,
)


def build_scorecard(
    scenarios: list[Scenario],
    results: list[ReplayResult],
    rules: RuleSet,
    *,
    benign: BenignReport | None = None,
    robustness: RobustnessReport | None = None,
) -> Scorecard:
    """Aggregate replay results into a :class:`Scorecard`.

    ``benign`` and ``robustness`` are optional extra measurements (false positives on a benign
    corpus, evasion sweep); they are carried on the scorecard but never affect the gate.
    """
    by_id = {r.scenario_id: r for r in results}
    missing = [s.id for s in scenarios if s.id not in by_id]
    if missing:
        raise ValueError(f"no replay result for scenario(s): {', '.join(missing)}")

    scenario_scores = [_score_scenario(s, by_id[s.id], rules) for s in scenarios]
    rule_scores = _score_rules(scenarios, by_id, rules)
    technique_scores = _score_techniques(scenarios, scenario_scores)
    totals = _totals(scenario_scores, rule_scores)
    gate = apply_gate(scenario_scores)
    return Scorecard(
        tripline_version=__version__,
        totals=totals,
        rules=rule_scores,
        scenarios=scenario_scores,
        techniques=technique_scores,
        gate=gate,
        benign=benign,
        robustness=robustness,
    )


def apply_gate(scenario_scores: list[ScenarioScore]) -> GateResult:
    """Fail when any scenario with fixtures has an expected rule that did not fire."""
    failures = [
        f"{s.scenario_id} ({s.technique}): expected rule(s) did not fire: " + _missing_text(s)
        for s in scenario_scores
        if s.status is ScenarioStatus.FAILED
    ]
    return GateResult(passed=not failures, failures=failures)


_OUTCOME_NOTE = {
    RuleOutcome.NO_APPLICABLE_EVENTS: " [no applicable events: routing problem]",
    RuleOutcome.ERROR: " [could not be evaluated]",
}


def _missing_text(score: ScenarioScore) -> str:
    """Missing rule ids; a rule that never ran is annotated so it is not read as a miss."""
    outcome = {e.rule_id: e.outcome for e in score.evidence}
    return ", ".join(
        rid + (_OUTCOME_NOTE[outcome[rid]] if outcome.get(rid) in _OUTCOME_NOTE else "")
        for rid in score.missing_rules
    )


def weighted_coverage(pairs: list[tuple[int, float]]) -> float | None:
    """``sum(weight x coverage) / sum(weight)``; ``None`` for an empty input."""
    total_weight = sum(w for w, _ in pairs)
    if total_weight == 0:
        return None
    return sum(w * c for w, c in pairs) / total_weight


def write_junit(results: list[ReplayResult], scenarios: list[Scenario], path: Path) -> None:
    """Write a JUnit XML report: one testcase per scenario, failures name the missed rules.

    GitHub renders this natively through test-reporter actions, and the failure message is
    what gets read first - so it names the scenario, the technique and the rule.
    """
    by_id = {s.id: s for s in scenarios}
    suite = ET.Element("testsuite", name="tripline.replay")
    counts = {"tests": 0, "failures": 0, "skipped": 0}
    for result in results:
        scenario = by_id[result.scenario_id]
        case = ET.SubElement(
            suite,
            "testcase",
            classname=f"tripline.replay.{scenario.plane.value}",
            name=f"{scenario.id} [{scenario.technique}]",
        )
        counts["tests"] += 1
        if result.status is ScenarioStatus.PENDING:
            counts["skipped"] += 1
            ET.SubElement(case, "skipped", message="no fixtures committed yet")
        elif result.status is ScenarioStatus.FAILED:
            counts["failures"] += 1
            lines = [
                f"{hit.rule_id} ({hit.title or 'unknown rule'}): "
                + (
                    f"0 of {hit.evaluated} applicable events matched"
                    if hit.outcome is RuleOutcome.MISSED
                    else describe_outcome(hit, result.events)
                )
                for hit in result.rules
                if not hit.fired
            ]
            failure = ET.SubElement(
                case,
                "failure",
                message=f"{scenario.id}: {len(lines)} expected rule(s) did not fire",
            )
            failure.text = "\n".join(lines)
    for key, value in counts.items():
        suite.set(key, str(value))
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def write_scorecard(scorecard: Scorecard, path: Path) -> None:
    """Serialise the scorecard as indented JSON (stable key order for clean diffs)."""
    write_text_lf(path, scorecard.model_dump_json(indent=2) + "\n")


def read_scorecard(path: Path) -> Scorecard:
    """Load a previously written ``scorecard.json``."""
    return Scorecard.model_validate_json(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- internals


def is_authored(compiled: CompiledRule | None) -> bool:
    """True for rules written for this project: their ``author`` field names tripline."""
    author = (compiled.rule.author or "") if compiled else ""
    return "tripline" in author.lower()


def _score_scenario(scenario: Scenario, result: ReplayResult, rules: RuleSet) -> ScenarioScore:
    fired = [h.rule_id for h in result.rules if h.fired]
    return ScenarioScore(
        scenario_id=scenario.id,
        name=scenario.name,
        plane=scenario.plane,
        technique=scenario.technique,
        tactic=scenario.tactic,
        weight=scenario.weight,
        status=result.status,
        provenance=sorted({f.provenance for f in scenario.fixtures}),
        events=result.events,
        expected_rules=list(scenario.expected_rules),
        needs_authored_rule=any(is_authored(rules.by_id(r)) for r in scenario.expected_rules),
        fired_rules=fired,
        missing_rules=[] if result.status is ScenarioStatus.PENDING else result.missing_rules,
        evidence=[
            RuleEvidence(
                rule_id=h.rule_id,
                title=h.title,
                fired=h.fired,
                hits=h.hits,
                evaluated=h.evaluated,
                error=h.error,
                outcome=(
                    RuleOutcome.PENDING if result.status is ScenarioStatus.PENDING else h.outcome
                ),
            )
            for h in result.rules
        ],
    )


def _score_rules(
    scenarios: list[Scenario], results: dict[str, ReplayResult], rules: RuleSet
) -> list[RuleScore]:
    expecting: dict[str, list[Scenario]] = defaultdict(list)
    for scenario in scenarios:
        for rule_id in scenario.expected_rules:
            expecting[rule_id].append(scenario)

    scores: list[RuleScore] = []
    for rule_id in sorted(expecting):
        detected: list[str] = []
        missed: list[str] = []
        pending: list[str] = []
        for scenario in expecting[rule_id]:
            result = results[scenario.id]
            if result.status is ScenarioStatus.PENDING:
                pending.append(scenario.id)
            elif any(h.rule_id == rule_id and h.fired for h in result.rules):
                detected.append(scenario.id)
            else:
                missed.append(scenario.id)
        scored = len(detected) + len(missed)
        compiled = rules.by_id(rule_id)
        level = compiled.rule.level if compiled else None
        scores.append(
            RuleScore(
                rule_id=rule_id,
                title=compiled.title if compiled else "<rule not loaded>",
                level=str(level.name).lower() if level else None,
                authored=is_authored(compiled),
                logsource=_logsource_text(compiled) if compiled else "",
                techniques=list(compiled.techniques) if compiled else [],
                expected_scenarios=[s.id for s in expecting[rule_id]],
                detected_scenarios=detected,
                missed_scenarios=missed,
                pending_scenarios=pending,
                coverage=(len(detected) / scored) if scored else None,
            )
        )
    return scores


def _logsource_text(compiled: CompiledRule) -> str:
    source = compiled.rule.logsource
    parts = [
        f"{key}={value}"
        for key, value in (
            ("product", source.product),
            ("category", source.category),
            ("service", source.service),
        )
        if value
    ]
    return " ".join(parts)


def _score_techniques(
    scenarios: list[Scenario], scenario_scores: list[ScenarioScore]
) -> list[TechniqueCoverage]:
    by_technique: dict[str, list[tuple[Scenario, ScenarioScore]]] = defaultdict(list)
    status = {s.scenario_id: s for s in scenario_scores}
    for scenario in scenarios:
        by_technique[scenario.technique].append((scenario, status[scenario.id]))

    coverage: list[TechniqueCoverage] = []
    for technique in sorted(by_technique):
        group = by_technique[technique]
        passed = sum(1 for _, score in group if score.status is ScenarioStatus.PASSED)
        rules = sorted({rid for scenario, _ in group for rid in scenario.expected_rules})
        coverage.append(
            TechniqueCoverage(
                technique=technique,
                weight=max(s.weight for s, _ in group),
                scenarios=[s.id for s, _ in group],
                rules=rules,
                coverage=passed / len(group),
                pending=all(score.status is ScenarioStatus.PENDING for _, score in group),
            )
        )
    return coverage


def _totals(scenario_scores: list[ScenarioScore], rule_scores: list[RuleScore]) -> ScorecardTotals:
    def value(score: ScenarioScore) -> float:
        return 1.0 if score.status is ScenarioStatus.PASSED else 0.0

    everything = [(s.weight, value(s)) for s in scenario_scores]
    scored = [
        (s.weight, value(s)) for s in scenario_scores if s.status is not ScenarioStatus.PENDING
    ]
    passed = [s for s in scenario_scores if s.status is ScenarioStatus.PASSED]
    vendored = [s for s in passed if not s.needs_authored_rule]
    return ScorecardTotals(
        scenarios=len(scenario_scores),
        passed=sum(1 for s in scenario_scores if s.status is ScenarioStatus.PASSED),
        failed=sum(1 for s in scenario_scores if s.status is ScenarioStatus.FAILED),
        pending=sum(1 for s in scenario_scores if s.status is ScenarioStatus.PENDING),
        rules=len(rule_scores),
        weighted_coverage=weighted_coverage(everything) or 0.0,
        weighted_coverage_scored=weighted_coverage(scored),
        passed_vendored_only=sum(1 for s in passed if not s.needs_authored_rule),
        passed_needs_authored=sum(1 for s in passed if s.needs_authored_rule),
        weighted_coverage_vendored=weighted_coverage(
            [(s.weight, 1.0 if s in vendored else 0.0) for s in scenario_scores]
        )
        or 0.0,
    )
