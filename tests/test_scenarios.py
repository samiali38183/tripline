"""Scenario loader tests: strict validation and the committed scenarios themselves."""

from __future__ import annotations

from pathlib import Path

import pytest

from tripline.engine.rules import load_rules
from tripline.models import EmulationKind, Plane, Provenance
from tripline.scenarios import (
    ScenarioLoadError,
    load_scenario,
    load_scenarios,
    validate_fixture_paths,
)

VALID = """
id: t1562-008-example
name: "Example"
plane: aws
technique: T1562.008
tactic: defense-evasion
weight: 3
emulation:
  kind: replay
  description: replayed detonation
  source: https://example.invalid/log.json
expected_rules:
  - 4db60cc0-36fb-42b7-9b58-a5b53019fb74
fixtures:
  - path: fixtures/cloud/example/run.ndjson
    provenance: recorded
    source: https://example.invalid/log.json
"""


def _write(tmp_path: Path, text: str, name: str = "s.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_scenario_loads(tmp_path):
    scenario = load_scenario(_write(tmp_path, VALID))
    assert scenario.plane is Plane.AWS
    assert scenario.emulation.kind is EmulationKind.REPLAY
    assert scenario.parent_technique == "T1562"
    assert scenario.fixtures[0].provenance is Provenance.RECORDED


@pytest.mark.parametrize(
    ("mutation", "needle"),
    [
        ("technique: T1562.008", "technique: 1562"),
        ("weight: 3", "weight: 11"),
        ("id: t1562-008-example", "id: Bad_Id"),
        ("tactic: defense-evasion", "tactic: ''"),
    ],
)
def test_invalid_field_values_rejected(tmp_path, mutation, needle):
    with pytest.raises(ScenarioLoadError):
        load_scenario(_write(tmp_path, VALID.replace(mutation, needle)))


def test_unknown_key_rejected(tmp_path):
    with pytest.raises(ScenarioLoadError, match="Extra inputs"):
        load_scenario(_write(tmp_path, VALID + "\nsurprise: 1\n"))


def test_replay_requires_source(tmp_path):
    text = VALID.replace(
        "  source: https://example.invalid/log.json\nexpected_rules", "expected_rules"
    )
    with pytest.raises(ScenarioLoadError, match="source"):
        load_scenario(_write(tmp_path, text))


def test_atomic_requires_guid(tmp_path):
    text = VALID.replace("kind: replay", "kind: atomic")
    with pytest.raises(ScenarioLoadError, match="atomic_tests"):
        load_scenario(_write(tmp_path, text))


def test_recorded_fixture_requires_source(tmp_path):
    text = VALID.replace("    source: https://example.invalid/log.json\n", "")
    with pytest.raises(ScenarioLoadError, match="source"):
        load_scenario(_write(tmp_path, text))


def test_duplicate_expected_rules_rejected(tmp_path):
    text = VALID + "  - 4db60cc0-36fb-42b7-9b58-a5b53019fb74\n"
    text = text.replace(
        "expected_rules:\n  - 4db60cc0-36fb-42b7-9b58-a5b53019fb74\nfixtures",
        "expected_rules:\n  - 4db60cc0-36fb-42b7-9b58-a5b53019fb74\n  - 4db60cc0-36fb-42b7-9b58-a5b53019fb74\nfixtures",
    )
    with pytest.raises(ScenarioLoadError, match="duplicates"):
        load_scenario(_write(tmp_path, text.rsplit("  - 4db60cc0", 1)[0]))


def test_duplicate_fixture_paths_rejected(tmp_path):
    dup = VALID + "  - path: fixtures/cloud/example/run.ndjson\n    provenance: synthetic\n"
    with pytest.raises(ScenarioLoadError, match="same path twice"):
        load_scenario(_write(tmp_path, dup))


def test_invalid_yaml_reports_path(tmp_path):
    with pytest.raises(ScenarioLoadError, match="invalid YAML"):
        load_scenario(_write(tmp_path, "id: [unclosed"))


def test_duplicate_ids_across_files_rejected(tmp_path):
    _write(tmp_path, VALID, "a.yaml")
    _write(tmp_path, VALID, "b.yaml")
    with pytest.raises(ScenarioLoadError, match="duplicate scenario id"):
        load_scenarios(tmp_path)


def test_empty_directory_rejected(tmp_path):
    with pytest.raises(ScenarioLoadError, match=r"no \*\.yaml"):
        load_scenarios(tmp_path)


def test_missing_fixture_path_reported(tmp_path):
    scenario = load_scenario(_write(tmp_path, VALID))
    problems = validate_fixture_paths([scenario], tmp_path)
    assert problems == [
        "t1562-008-example: fixture fixtures\\cloud\\example\\run.ndjson not found"
    ] or problems == ["t1562-008-example: fixture fixtures/cloud/example/run.ndjson not found"]


# --------------------------------------------------------------------------- committed scenarios


def test_committed_scenarios_cover_design_table(repo_root):
    scenarios = load_scenarios(repo_root / "scenarios")
    techniques = {s.technique for s in scenarios}
    assert len(scenarios) == 14
    assert techniques == {
        "T1078.004",
        "T1530",
        "T1562.008",
        "T1098.001",
        "T1059.001",
        "T1059.003",
        "T1105",
        "T1047",
        "T1027",
        "T1003.001",
        "T1053.005",
        "T1053.003",
        "T1070.003",
        "T1548.001",
    }
    planes = {p: sum(1 for s in scenarios if s.plane is p) for p in Plane}
    assert planes == {Plane.AWS: 4, Plane.WINDOWS: 7, Plane.LINUX: 3}


def test_committed_scenarios_reference_existing_rules_and_fixtures(repo_root):
    scenarios = load_scenarios(repo_root / "scenarios")
    rules = load_rules(repo_root / "rules" / "sigma")
    assert not rules.errors, rules.errors
    known = rules.ids()
    for scenario in scenarios:
        for rule_id in scenario.expected_rules:
            assert rule_id in known, f"{scenario.id} expects unknown rule {rule_id}"
    assert validate_fixture_paths(scenarios, repo_root) == []


def test_every_cloud_scenario_has_recorded_fixtures(repo_root):
    scenarios = load_scenarios(repo_root / "scenarios")
    for scenario in scenarios:
        if scenario.plane is Plane.AWS:
            assert scenario.fixtures, scenario.id
            assert all(f.provenance is Provenance.RECORDED for f in scenario.fixtures)
