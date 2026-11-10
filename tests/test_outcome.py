"""A rule with no applicable events is a routing problem, not a detection miss."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tripline.cli import app, scorecard_markdown
from tripline.engine.rules import load_rules
from tripline.events import write_ndjson
from tripline.models import (
    Emulation,
    EmulationKind,
    Fixture,
    Plane,
    Provenance,
    RuleOutcome,
    Scenario,
    Scorecard,
)
from tripline.replay import replay_scenario
from tripline.report import render_html
from tripline.scorer import build_scorecard, read_scorecard, write_junit

AWS_RULE = "4db60cc0-36fb-42b7-9b58-a5b53019fb74"  # cloudtrail
LINUX_RULE = "7f3c2b1a-6d4e-4a9b-9c8d-1e2f3a4b5c6d"  # linux process_creation
STOP = {
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "eventTime": "2024-07-31T13:06:24Z",
    "userIdentity": {"type": "IAMUser"},
}
OTHER = {
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "ListBuckets",
    "eventTime": "2024-07-31T13:06:25Z",
    "userIdentity": {"type": "IAMUser"},
}
runner = CliRunner()


@pytest.fixture
def ruleset(repo_root):
    return load_rules(repo_root / "rules" / "sigma")


def _scenario(rules: list[str], *, with_fixture: bool = True) -> Scenario:
    return Scenario(
        id="t1562-008-test",
        name="test",
        plane=Plane.AWS,
        technique="T1562.008",
        tactic="defense-evasion",
        weight=3,
        emulation=Emulation(kind=EmulationKind.REPLAY, description="x", source="https://e.invalid"),
        expected_rules=rules,
        fixtures=[Fixture(path=Path("f.ndjson"), provenance=Provenance.SYNTHETIC)]
        if with_fixture
        else [],
    )


def _replay(tmp_path, ruleset, rules, events, **kwargs):
    write_ndjson(tmp_path / "f.ndjson", events)
    scenario = _scenario(rules, **kwargs)
    return scenario, replay_scenario(scenario, ruleset, tmp_path)


def test_outcomes_are_distinguished(tmp_path, ruleset):
    _, matched = _replay(tmp_path, ruleset, [AWS_RULE], [STOP, OTHER])
    assert matched.rules[0].outcome is RuleOutcome.MATCHED
    _, missed = _replay(tmp_path, ruleset, [AWS_RULE], [OTHER])
    assert missed.rules[0].outcome is RuleOutcome.MISSED
    assert missed.rules[0].evaluated == 1
    _, routing = _replay(tmp_path, ruleset, [LINUX_RULE], [STOP, OTHER])
    assert routing.rules[0].outcome is RuleOutcome.NO_APPLICABLE_EVENTS
    _, unknown = _replay(tmp_path, ruleset, ["00000000-0000-0000-0000-000000000000"], [STOP])
    assert unknown.rules[0].outcome is RuleOutcome.ERROR
    _, pending = _replay(tmp_path, ruleset, [AWS_RULE], [], with_fixture=False)
    assert pending.rules[0].outcome is RuleOutcome.PENDING


def test_scorecard_evidence_and_gate_message(tmp_path, ruleset):
    scenario, result = _replay(tmp_path, ruleset, [LINUX_RULE, AWS_RULE], [OTHER])
    card = build_scorecard([scenario], [result], ruleset)
    outcomes = {e.rule_id: e.outcome for e in card.scenarios[0].evidence}
    assert outcomes == {
        LINUX_RULE: RuleOutcome.NO_APPLICABLE_EVENTS,
        AWS_RULE: RuleOutcome.MISSED,
    }
    (failure,) = card.gate.failures
    assert f"{LINUX_RULE} [no applicable events: routing problem]" in failure
    assert f"{AWS_RULE}" in failure and f"{AWS_RULE} [" not in failure


def test_junit_text_separates_routing_from_miss(tmp_path, ruleset):
    scenario, result = _replay(tmp_path, ruleset, [LINUX_RULE, AWS_RULE], [OTHER])
    write_junit([result], [scenario], tmp_path / "j.xml")
    text = (tmp_path / "j.xml").read_text(encoding="utf-8")
    assert "routing problem" in text and "0 of 0" not in text
    assert "0 of 1 applicable events matched" in text


def test_html_report_separates_routing_from_miss(tmp_path, ruleset):
    scenario, result = _replay(tmp_path, ruleset, [LINUX_RULE, AWS_RULE], [OTHER])
    html = render_html(build_scorecard([scenario], [result], ruleset))
    assert "no applicable events" in html and "routing problem" in html
    assert "0/1 applicable events" in html
    assert "0/0 applicable events" not in html


def test_markdown_flags_routing_problem(tmp_path, ruleset):
    scenario, result = _replay(tmp_path, ruleset, [LINUX_RULE], [OTHER])
    md = scorecard_markdown(build_scorecard([scenario], [result], ruleset))
    assert "routing problem" in md


def test_scorecard_schema_is_additive(tmp_path, ruleset):
    """Scorecards written before this field (0.2.0 and earlier) must still load."""
    scenario, result = _replay(tmp_path, ruleset, [LINUX_RULE, AWS_RULE], [OTHER])
    data = json.loads(build_scorecard([scenario], [result], ruleset).model_dump_json())
    for item in data["scenarios"][0]["evidence"]:
        del item["outcome"]
    card = Scorecard.model_validate(data)
    got = {e.rule_id: e.outcome for e in card.scenarios[0].evidence}
    assert got[LINUX_RULE] is RuleOutcome.NO_APPLICABLE_EVENTS  # derived from the counts
    assert got[AWS_RULE] is RuleOutcome.MISSED
    del data["scenarios"][0]["evidence"]  # 0.1.x shape
    assert Scorecard.model_validate(data).scenarios[0].evidence == []


def test_committed_scorecard_still_loads_and_has_outcomes(repo_root):
    card = read_scorecard(repo_root / "docs" / "scorecard.json")
    assert all(e.outcome is not None for s in card.scenarios for e in s.evidence)


def test_cli_replay_prints_routing_problem(repo_root, tmp_path):
    for folder in ("scenarios", "rules", "fixtures"):
        shutil.copytree(repo_root / folder, tmp_path / folder)
    path = tmp_path / "scenarios" / "t1562-008-cloudtrail-stop.yaml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(AWS_RULE, LINUX_RULE), encoding="utf-8"
    )
    result = runner.invoke(app, ["replay", "t1562-008-cloudtrail-stop", "--root", str(tmp_path)])
    assert result.exit_code == 1
    assert "no applicable events" in result.output and "routing problem" in result.output
    assert "0/0 applicable" not in result.output
