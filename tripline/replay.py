"""Replay committed NDJSON fixtures through the Sigma rules a scenario expects.

This is the container-free evaluator: it needs only the repository checkout, so the same
code gates pull requests on a plain GitHub runner and runs on a developer laptop with
``tripline replay --all``.
"""

from __future__ import annotations

from pathlib import Path

from tripline.engine.rules import RuleSet, evaluate
from tripline.events import read_ndjson
from tripline.models import Event, ReplayResult, RuleHit, RuleOutcome, Scenario, ScenarioStatus


def load_fixture_events(scenario: Scenario, root: Path) -> list[Event]:
    """Concatenate every fixture of ``scenario`` (paths are relative to ``root``)."""
    events: list[Event] = []
    for fixture in scenario.fixtures:
        events.extend(read_ndjson(root / fixture.path))
    return events


def replay_scenario(scenario: Scenario, rules: RuleSet, root: Path) -> ReplayResult:
    """Evaluate each expected rule over the scenario's fixtures.

    A scenario without fixtures is *pending*: reported, never gating. A scenario whose
    expected rule is absent from the rule set (bad UUID, failed to compile) is *failed*,
    because a gate that cannot evaluate a rule must not pass it.
    """
    fixture_paths = [str(f.path).replace("\\", "/") for f in scenario.fixtures]
    if not scenario.fixtures:
        hits = [
            RuleHit(
                rule_id=rid,
                title=_title(rules, rid),
                fired=False,
                hits=0,
                evaluated=0,
                outcome=RuleOutcome.PENDING,
            )
            for rid in scenario.expected_rules
        ]
        return ReplayResult(
            scenario_id=scenario.id,
            status=ScenarioStatus.PENDING,
            events=0,
            fixtures=fixture_paths,
            rules=hits,
        )

    events = load_fixture_events(scenario, root)
    hits = [_evaluate_rule(rule_id, rules, events) for rule_id in scenario.expected_rules]
    status = ScenarioStatus.PASSED if all(h.fired for h in hits) else ScenarioStatus.FAILED
    return ReplayResult(
        scenario_id=scenario.id,
        status=status,
        events=len(events),
        fixtures=fixture_paths,
        rules=hits,
    )


def replay_all(scenarios: list[Scenario], rules: RuleSet, root: Path) -> list[ReplayResult]:
    """Replay every scenario, in id order."""
    return [replay_scenario(s, rules, root) for s in sorted(scenarios, key=lambda s: s.id)]


def _evaluate_rule(rule_id: str, rules: RuleSet, events: list[Event]) -> RuleHit:
    compiled = rules.by_id(rule_id)
    if compiled is None:
        reason = next((e.reason for e in rules.errors if rule_id in e.reason), None)
        return RuleHit(
            rule_id=rule_id,
            title=None,
            fired=False,
            hits=0,
            evaluated=0,
            error=reason or "rule id not found in rule set",
        )
    matched = 0
    evaluated = 0
    first: Event | None = None
    for event in events:
        verdict = evaluate(compiled, event)
        if verdict is None:
            continue
        evaluated += 1
        if verdict:
            matched += 1
            if first is None:
                first = event
    return RuleHit(
        rule_id=rule_id,
        title=compiled.title,
        fired=matched > 0,
        hits=matched,
        evaluated=evaluated,
        first_match=first,
    )


def _title(rules: RuleSet, rule_id: str) -> str | None:
    compiled = rules.by_id(rule_id)
    return compiled.title if compiled else None
