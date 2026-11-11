"""Heatmap tests: Navigator layer shape, gradient scores, grey known-gap cells."""

from __future__ import annotations

import json
from pathlib import Path

from tripline.engine.rules import load_rules
from tripline.heatmap import GAP_COLOR, KNOWN_GAPS, PENDING_COLOR, build_layer, write_layer
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
from tripline.scorer import build_scorecard

R1 = "4db60cc0-36fb-42b7-9b58-a5b53019fb74"
FIX = Fixture(path=Path("x.ndjson"), provenance=Provenance.RECORDED, source="https://e.invalid")


def _card(repo_root):
    rules = load_rules(repo_root / "rules" / "sigma")
    scenarios = [
        Scenario(
            id="a",
            name="a",
            plane=Plane.AWS,
            technique="T1562.008",
            tactic="x",
            weight=3,
            emulation=Emulation(
                kind=EmulationKind.REPLAY, description="x", source="https://e.invalid"
            ),
            expected_rules=[R1],
            fixtures=[FIX],
        ),
        Scenario(
            id="b",
            name="b",
            plane=Plane.WINDOWS,
            technique="T1105",
            tactic="x",
            weight=6,
            emulation=Emulation(kind=EmulationKind.ATOMIC, description="x", atomic_tests=["g"]),
            expected_rules=[R1],
        ),
    ]
    results = [
        ReplayResult(
            scenario_id="a",
            status=ScenarioStatus.PASSED,
            events=1,
            fixtures=[],
            rules=[RuleHit(rule_id=R1, title="t", fired=True, hits=1, evaluated=1)],
        ),
        ReplayResult(
            scenario_id="b",
            status=ScenarioStatus.PENDING,
            events=0,
            fixtures=[],
            rules=[RuleHit(rule_id=R1, title="t", fired=False, hits=0, evaluated=0)],
        ),
    ]
    return build_scorecard(scenarios, results, rules)


def test_layer_shape_and_versions(repo_root):
    layer = build_layer(_card(repo_root))
    assert layer["versions"] == {"attack": "20", "navigator": "5.1.0", "layer": "4.5"}
    assert layer["domain"] == "enterprise-attack"
    assert layer["gradient"]["minValue"] == 0 and layer["gradient"]["maxValue"] == 100
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert ids == ["T1105", "T1562.008", *sorted(KNOWN_GAPS)]


def test_scored_pending_and_gap_cells(repo_root):
    cells = {t["techniqueID"]: t for t in build_layer(_card(repo_root))["techniques"]}
    assert cells["T1562.008"]["score"] == 100 and "color" not in cells["T1562.008"]
    assert cells["T1105"]["score"] == 0 and cells["T1105"]["color"] == PENDING_COLOR
    assert "fixtures pending" in cells["T1105"]["comment"]
    for gap in KNOWN_GAPS:
        assert cells[gap]["color"] == GAP_COLOR and "score" not in cells[gap]
        assert cells[gap]["comment"].startswith("KNOWN GAP")
    weight = next(m for m in cells["T1562.008"]["metadata"] if m["name"] == "weight")
    assert weight["value"] == "3"


def test_write_layer_is_valid_json_with_lf(repo_root, tmp_path):
    out = tmp_path / "layer.json"
    layer = write_layer(_card(repo_root), out)
    assert json.loads(out.read_text(encoding="utf-8")) == layer
    assert b"\r\n" not in out.read_bytes()


def test_committed_layer_has_14_plus_3_cells(repo_root):
    layer = json.loads((repo_root / "docs" / "navigator_layer.json").read_text(encoding="utf-8"))
    cells = {t["techniqueID"]: t for t in layer["techniques"]}
    assert len(cells) == 17
    assert sum(1 for c in cells.values() if c.get("color") == GAP_COLOR) == 3
