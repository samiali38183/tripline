"""Replay tests: fixture loading, pass/fail/pending semantics, the committed cloud fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tripline.cloud.replay import (
    load_stratus_log,
    replay_records,
    run_guid_of,
    select,
    select_many,
    time_window,
)
from tripline.engine.rules import load_rules
from tripline.events import read_ndjson, write_ndjson
from tripline.models import (
    Emulation,
    EmulationKind,
    Fixture,
    Plane,
    Provenance,
    Scenario,
    ScenarioStatus,
)
from tripline.replay import replay_all, replay_scenario
from tripline.scenarios import load_scenarios

STOP_LOGGING = {
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "eventTime": "2024-07-31T13:06:24Z",
    "userAgent": "aws-cli/2.0",
    "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/x"},
}
RULE_STOP = "4db60cc0-36fb-42b7-9b58-a5b53019fb74"
RULE_ROOT = "8ad1600d-e9dc-4251-b0ee-a65268f29add"


def _scenario(fixtures: list[Fixture], rules: list[str]) -> Scenario:
    return Scenario(
        id="t1562-008-test",
        name="test",
        plane=Plane.AWS,
        technique="T1562.008",
        tactic="defense-evasion",
        weight=3,
        emulation=Emulation(kind=EmulationKind.REPLAY, description="x", source="https://e.invalid"),
        expected_rules=rules,
        fixtures=fixtures,
    )


@pytest.fixture
def ruleset(repo_root):
    return load_rules(repo_root / "rules" / "sigma")


def test_pass_when_every_expected_rule_fires(tmp_path, ruleset):
    write_ndjson(tmp_path / "f.ndjson", [STOP_LOGGING])
    scenario = _scenario(
        [Fixture(path=Path("f.ndjson"), provenance=Provenance.SYNTHETIC)], [RULE_STOP]
    )
    result = replay_scenario(scenario, ruleset, tmp_path)
    assert result.status is ScenarioStatus.PASSED
    assert result.events == 1
    assert result.rules[0].hits == 1 and result.rules[0].evaluated == 1
    assert result.rules[0].first_match == STOP_LOGGING
    assert result.missing_rules == []


def test_fail_when_a_rule_does_not_fire(tmp_path, ruleset):
    write_ndjson(tmp_path / "f.ndjson", [STOP_LOGGING])
    scenario = _scenario(
        [Fixture(path=Path("f.ndjson"), provenance=Provenance.SYNTHETIC)], [RULE_STOP, RULE_ROOT]
    )
    result = replay_scenario(scenario, ruleset, tmp_path)
    assert result.status is ScenarioStatus.FAILED
    assert result.missing_rules == [RULE_ROOT]
    missed = result.rules[1]
    assert missed.evaluated == 1 and missed.hits == 0 and missed.error is None


def test_fail_when_expected_rule_is_unknown(tmp_path, ruleset):
    write_ndjson(tmp_path / "f.ndjson", [STOP_LOGGING])
    scenario = _scenario(
        [Fixture(path=Path("f.ndjson"), provenance=Provenance.SYNTHETIC)],
        ["00000000-0000-0000-0000-000000000000"],
    )
    result = replay_scenario(scenario, ruleset, tmp_path)
    assert result.status is ScenarioStatus.FAILED
    assert result.rules[0].error == "rule id not found in rule set"


def test_pending_without_fixtures(ruleset, tmp_path):
    result = replay_scenario(_scenario([], [RULE_STOP]), ruleset, tmp_path)
    assert result.status is ScenarioStatus.PENDING
    assert result.events == 0
    assert result.rules[0].title == "AWS CloudTrail Important Change"


def test_rule_not_applicable_to_logsource_counts_zero_evaluated(tmp_path, ruleset):
    windows_event = {"Channel": "Security", "EventID": 4698, "SubjectUserName": "bob"}
    write_ndjson(tmp_path / "f.ndjson", [windows_event])
    scenario = _scenario(
        [Fixture(path=Path("f.ndjson"), provenance=Provenance.SYNTHETIC)], [RULE_STOP]
    )
    result = replay_scenario(scenario, ruleset, tmp_path)
    assert result.status is ScenarioStatus.FAILED
    assert result.rules[0].evaluated == 0


def test_malformed_ndjson_reports_line(tmp_path):
    path = tmp_path / "bad.ndjson"
    path.write_text('{"a": 1}\nnot json\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"bad\.ndjson:2"):
        read_ndjson(path)


# --------------------------------------------------------------------------- cloud replay helpers


def test_replay_records_rebases_time_and_tags_user_agent():
    records = [
        {**STOP_LOGGING, "eventTime": "2024-07-31T13:06:24Z"},
        {**STOP_LOGGING, "eventTime": "2024-07-31T13:08:24Z", "userAgent": None},
    ]
    from datetime import UTC, datetime

    base = datetime(2026, 1, 1, tzinfo=UTC)
    out = replay_records(records, run_guid="abc", base_time=base)
    assert [r["eventTime"] for r in out] == ["2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z"]
    assert out[0]["userAgent"] == "aws-cli/2.0 tripline/abc"
    assert out[1]["userAgent"] == "tripline/abc"
    assert run_guid_of(out[0]) == "abc"
    assert run_guid_of(STOP_LOGGING) is None
    assert records[0]["eventTime"] == "2024-07-31T13:06:24Z"  # input untouched
    assert time_window(out) == ("2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z")


def test_select_and_select_many_stop_early():
    stream = iter([{"eventName": n, "eventSource": "s"} for n in ["A", "B", "A", "B", "C"]])
    picked = select(stream, lambda r: r["eventName"] == "A", limit=1)
    assert len(picked) == 1
    rest = list(stream)
    assert [r["eventName"] for r in rest] == [
        "B",
        "A",
        "B",
        "C",
    ]  # one record consumed past the hit at most
    many = select_many(
        iter(rest),
        {"a": (lambda r: r["eventName"] == "A", 1), "b": (lambda r: r["eventName"] == "B", 1)},
    )
    assert {k: len(v) for k, v in many.items()} == {"a": 1, "b": 1}


def test_load_stratus_log_validates_shape(tmp_path):
    good = tmp_path / "g.json"
    good.write_text(json.dumps([STOP_LOGGING]), encoding="utf-8")
    assert load_stratus_log(good) == [STOP_LOGGING]
    bad = tmp_path / "b.json"
    bad.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_stratus_log(bad)


# --------------------------------------------------------------------------- committed fixtures


def test_committed_fixtures_all_pass(repo_root, ruleset):
    scenarios = [
        s for s in load_scenarios(repo_root / "scenarios") if s.plane in {Plane.AWS, Plane.LINUX}
    ]
    results = replay_all(scenarios, ruleset, repo_root)
    assert len(results) == 7  # 4 AWS + 3 Linux recorded on the runner
    for result in results:
        assert result.status is ScenarioStatus.PASSED, (result.scenario_id, result.missing_rules)
        assert result.events > 0


def test_committed_fixtures_are_guid_tagged_and_match_manifest(repo_root):
    """Cloud events carry the GUID in userAgent, Linux events in the ``tripline`` object."""
    for scenario in load_scenarios(repo_root / "scenarios"):
        for fixture in scenario.fixtures:
            events = read_ndjson(repo_root / fixture.path)
            manifest = json.loads(
                (repo_root / fixture.path).with_name("manifest.json").read_text(encoding="utf-8")
            )
            if scenario.plane is Plane.AWS:
                guids = {run_guid_of(e) for e in events}
            else:
                guids = {e["tripline"]["run_guid"] for e in events}
                assert {e["tripline"]["atomic_test"] for e in events} <= set(
                    scenario.emulation.atomic_tests
                )
            assert guids == {manifest["run_guid"]}
            assert manifest["events"] == len(events)
            assert manifest["scenario_id"] == scenario.id
            assert fixture.source and fixture.source.startswith("https://")
