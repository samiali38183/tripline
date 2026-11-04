"""Scorer tests: coverage math, prevalence weights, gate, JUnit shape, JSON round-trip."""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from tripline.engine.rules import RuleSet, load_rules
from tripline.models import (
    Emulation,
    EmulationKind,
    Fixture,
    Plane,
    Provenance,
    ReplayResult,
    RuleHit,
    Scenario,
    ScenarioStatus,
)
from tripline.scorer import (
    apply_gate,
    build_scorecard,
    read_scorecard,
    weighted_coverage,
    write_junit,
    write_scorecard,
)

R1 = "4db60cc0-36fb-42b7-9b58-a5b53019fb74"  # AWS CloudTrail Important Change
R2 = "8ad1600d-e9dc-4251-b0ee-a65268f29add"  # AWS Root Credentials
FIX = Fixture(path=Path("x.ndjson"), provenance=Provenance.RECORDED, source="https://e.invalid")


def _scenario(
    sid: str, technique: str, weight: int, rules: list[str], *, fixtures: bool = True
) -> Scenario:
    return Scenario(
        id=sid,
        name=sid,
        plane=Plane.AWS,
        technique=technique,
        tactic="x",
        weight=weight,
        emulation=Emulation(kind=EmulationKind.REPLAY, description="x", source="https://e.invalid"),
        expected_rules=rules,
        fixtures=[FIX] if fixtures else [],
    )


def _result(sid: str, fired: dict[str, bool], *, pending: bool = False) -> ReplayResult:
    hits = [
        RuleHit(rule_id=r, title=r, fired=f, hits=int(f), evaluated=1) for r, f in fired.items()
    ]
    if pending:
        status = ScenarioStatus.PENDING
    else:
        status = ScenarioStatus.PASSED if all(fired.values()) else ScenarioStatus.FAILED
    return ReplayResult(
        scenario_id=sid, status=status, events=0 if pending else 1, fixtures=[], rules=hits
    )


@pytest.fixture(scope="module")
def ruleset() -> RuleSet:
    return load_rules(Path(__file__).resolve().parent.parent / "rules" / "sigma")


def test_weighted_coverage_math():
    assert weighted_coverage([]) is None
    assert weighted_coverage([(10, 1.0), (5, 0.0)]) == pytest.approx(10 / 15)
    assert weighted_coverage([(3, 0.5), (1, 1.0)]) == pytest.approx((1.5 + 1.0) / 4)


def test_scorecard_totals_and_weights(ruleset):
    scenarios = [
        _scenario("a-pass", "T1562.008", 3, [R1]),
        _scenario("b-fail", "T1078.004", 10, [R1, R2]),
        _scenario("c-pending", "T1530", 7, [R2], fixtures=False),
    ]
    results = [
        _result("a-pass", {R1: True}),
        _result("b-fail", {R1: True, R2: False}),
        _result("c-pending", {R2: False}, pending=True),
    ]
    card = build_scorecard(scenarios, results, ruleset)
    t = card.totals
    assert (t.scenarios, t.passed, t.failed, t.pending, t.rules) == (3, 1, 1, 1, 2)
    # weights: a=3 (pass), b=10 (fail), c=7 (pending -> 0)
    assert t.weighted_coverage == pytest.approx(3 / 20)
    assert t.weighted_coverage_scored == pytest.approx(3 / 13)
    assert not card.gate.passed
    assert card.gate.failures == [f"b-fail (T1078.004): expected rule(s) did not fire: {R2}"]


def test_rule_scores(ruleset):
    scenarios = [
        _scenario("a", "T1562.008", 3, [R1]),
        _scenario("b", "T1078.004", 10, [R1, R2]),
        _scenario("c", "T1530", 7, [R2], fixtures=False),
    ]
    results = [
        _result("a", {R1: True}),
        _result("b", {R1: True, R2: False}),
        _result("c", {R2: False}, pending=True),
    ]
    card = build_scorecard(scenarios, results, ruleset)
    r1, r2 = card.rule(R1), card.rule(R2)
    assert r1 is not None and r2 is not None
    assert r1.coverage == 1.0 and r1.detected_scenarios == ["a", "b"]
    assert (
        r1.title == "AWS CloudTrail Important Change"
        and r1.logsource == "product=aws service=cloudtrail"
    )
    assert r1.level == "medium"
    assert r2.coverage == 0.0 and r2.missed_scenarios == ["b"] and r2.pending_scenarios == ["c"]


def test_rule_score_when_every_scenario_pending(ruleset):
    scenarios = [_scenario("c", "T1530", 7, [R2], fixtures=False)]
    card = build_scorecard(scenarios, [_result("c", {R2: False}, pending=True)], ruleset)
    assert card.rule(R2).coverage is None
    assert card.totals.weighted_coverage == 0.0
    assert card.totals.weighted_coverage_scored is None
    assert card.gate.passed  # pending never gates


def test_technique_coverage_groups_scenarios(ruleset):
    scenarios = [
        _scenario("a", "T1105", 6, [R1]),
        _scenario("b", "T1105", 6, [R2]),
        _scenario("c", "T1530", 7, [R2], fixtures=False),
    ]
    results = [
        _result("a", {R1: True}),
        _result("b", {R2: False}),
        _result("c", {R2: False}, pending=True),
    ]
    card = build_scorecard(scenarios, results, ruleset)
    by = {t.technique: t for t in card.techniques}
    assert (
        by["T1105"].coverage == 0.5
        and by["T1105"].rules == sorted([R1, R2])
        and not by["T1105"].pending
    )
    assert by["T1530"].coverage == 0.0 and by["T1530"].pending


def test_missing_result_is_an_error(ruleset):
    with pytest.raises(ValueError, match="no replay result"):
        build_scorecard([_scenario("a", "T1105", 6, [R1])], [], ruleset)


def test_gate_only_fails_on_failed_status(ruleset):
    scenarios = [_scenario("a", "T1105", 6, [R1]), _scenario("c", "T1530", 7, [R2], fixtures=False)]
    card = build_scorecard(
        scenarios, [_result("a", {R1: True}), _result("c", {R2: False}, pending=True)], ruleset
    )
    assert apply_gate(card.scenarios).passed


def test_junit_shape(tmp_path):
    scenarios = [
        _scenario("a-pass", "T1562.008", 3, [R1]),
        _scenario("b-fail", "T1078.004", 10, [R1, R2]),
        _scenario("c-pending", "T1530", 7, [R2], fixtures=False),
    ]
    results = [
        _result("a-pass", {R1: True}),
        _result("b-fail", {R1: True, R2: False}),
        _result("c-pending", {R2: False}, pending=True),
    ]
    out = tmp_path / "junit.xml"
    write_junit(results, scenarios, out)
    suite = ET.parse(out).getroot()
    assert suite.tag == "testsuite"
    assert (suite.get("tests"), suite.get("failures"), suite.get("skipped")) == ("3", "1", "1")
    cases = {c.get("name"): c for c in suite.findall("testcase")}
    assert set(cases) == {"a-pass [T1562.008]", "b-fail [T1078.004]", "c-pending [T1530]"}
    failure = cases["b-fail [T1078.004]"].find("failure")
    assert failure is not None
    assert "b-fail" in failure.get("message", "") and R2 in (failure.text or "")
    assert cases["c-pending [T1530]"].find("skipped") is not None
    assert cases["a-pass [T1562.008]"].find("failure") is None


def test_scorecard_json_round_trip(tmp_path, ruleset):
    scenarios = [_scenario("a", "T1105", 6, [R1])]
    card = build_scorecard(scenarios, [_result("a", {R1: True})], ruleset)
    path = tmp_path / "scorecard.json"
    write_scorecard(card, path)
    loaded = read_scorecard(path)
    assert loaded == card
    assert path.read_bytes().endswith(b"}\n") and b"\r\n" not in path.read_bytes()
