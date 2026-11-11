"""HTML report and SVG badge: tactic grouping, evidence, escaping, self-containment."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from typer.testing import CliRunner

from tripline.cli import app
from tripline.engine.rules import load_rules
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
from tripline.report import (
    UNKNOWN_TACTIC,
    render_badge,
    render_html,
    tactic_columns,
    weight_split,
)
from tripline.scorer import build_scorecard, read_scorecard

R1 = "4db60cc0-36fb-42b7-9b58-a5b53019fb74"
FIX = Fixture(path=Path("x.ndjson"), provenance=Provenance.RECORDED, source="https://e.invalid")
runner = CliRunner()


def _scenario(sid, technique, tactic, weight, *, fixtures=True, name=None):
    return Scenario(
        id=sid,
        name=name or sid,
        plane=Plane.AWS if fixtures else Plane.WINDOWS,
        technique=technique,
        tactic=tactic,
        weight=weight,
        emulation=(
            Emulation(kind=EmulationKind.REPLAY, description="x", source="https://e.invalid")
            if fixtures
            else Emulation(kind=EmulationKind.ATOMIC, description="x", atomic_tests=["g"])
        ),
        expected_rules=[R1],
        fixtures=[FIX] if fixtures else [],
    )


def _result(sid, status, *, fired, hits=0, evaluated=0):
    return ReplayResult(
        scenario_id=sid,
        status=status,
        events=evaluated,
        fixtures=[],
        rules=[RuleHit(rule_id=R1, title="t", fired=fired, hits=hits, evaluated=evaluated)],
    )


def _card(repo_root):
    rules = load_rules(repo_root / "rules" / "sigma")
    scenarios = [
        _scenario("a", "T1685.002", "defense-impairment", 3),
        _scenario("b", "T1105", "command-and-control", 6, fixtures=False),
        _scenario("c", "T1078.004", "initial-access", 10),
        _scenario("d", "T1027", "defense-impairment", 1, name="<script>alert(1)</script>"),
        _scenario("e", "T1003", "not-a-tactic", 2),
    ]
    results = [
        _result("a", ScenarioStatus.PASSED, fired=True, hits=1, evaluated=4),
        _result("b", ScenarioStatus.PENDING, fired=False),
        _result("c", ScenarioStatus.FAILED, fired=False, evaluated=7),
        _result("d", ScenarioStatus.PASSED, fired=True, hits=2, evaluated=2),
        _result("e", ScenarioStatus.PASSED, fired=True, hits=1, evaluated=1),
    ]
    return build_scorecard(scenarios, results, rules)


def test_scorecard_carries_tactic_and_evidence(repo_root):
    card = _card(repo_root)
    a = card.scenario("a")
    assert a is not None and a.tactic == "defense-impairment"
    assert [(e.rule_id, e.hits, e.evaluated, e.fired) for e in a.evidence] == [(R1, 1, 4, True)]


def test_tactic_columns_kill_chain_order_and_weight_sort(repo_root):
    columns, empty = tactic_columns(_card(repo_root))
    assert [c.label for c in columns] == [
        "Initial Access",
        "Defense Impairment",
        "Command and Control",
        UNKNOWN_TACTIC,
    ]
    evasion = columns[1]
    assert [s.scenario_id for s in evasion.scenarios] == ["a", "d"]  # weight 3 before weight 1
    assert "Execution" in empty and "Defense Impairment" not in empty
    assert "Stealth" in empty and len(empty) == 15 - 3


def test_weight_split(repo_root):
    split = weight_split(_card(repo_root))
    assert (split.passed, split.failed, split.pending, split.total) == (6, 10, 6, 22)
    assert round(split.pct(split.failed), 2) == round(100 * 10 / 22, 2)


def test_html_is_self_contained_and_escaped(repo_root):
    html = render_html(_card(repo_root))
    assert html.startswith("<!doctype html>")
    assert "<script" not in html  # escaped scenario name, and no JS of our own
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # nothing loaded from the network: no src= or stylesheet links
    assert not re.search(r"""(src|href)=["']https?://(?!github\.com/samiali38183)""", html)
    assert "<link" not in html


def test_html_shows_gate_failure_and_counts(repo_root):
    html = render_html(_card(repo_root))
    assert "Gate failed" in html
    assert "c (T1078.004): expected rule(s) did not fire" in html
    assert "0/7 applicable events" in html
    assert "1/4 applicable events" in html
    assert "No scenarios yet:" in html and "Exfiltration" in html


def test_html_renders_committed_scorecard(repo_root):
    card = read_scorecard(repo_root / "docs" / "scorecard.json")
    html = render_html(card)
    assert "Gate passed" in html
    assert f"{card.totals.weighted_coverage * 100:.0f}%" in html
    for s in card.scenarios:
        assert s.technique in html


def test_old_scorecard_without_tactic_still_renders(repo_root):
    card = _card(repo_root)
    legacy = card.model_copy(
        update={
            "scenarios": [
                s.model_copy(update={"tactic": "", "evidence": []}) for s in card.scenarios
            ]
        }
    )
    columns, _ = tactic_columns(legacy)
    assert [c.label for c in columns] == [UNKNOWN_TACTIC]
    assert "AWS CloudTrail Important Change" in render_html(legacy)  # falls back to rule titles


def test_badge_is_valid_svg_with_value(repo_root):
    svg = render_badge(_card(repo_root))
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert root.get("aria-label") == "weighted coverage: 27%"
    assert "#c62828" in svg  # 27 % is below the 40 % amber threshold


def test_report_command_writes_html_and_badge(repo_root, tmp_path):
    out, badge = tmp_path / "r.html", tmp_path / "b.svg"
    result = runner.invoke(
        app,
        [
            "report",
            str(repo_root / "docs" / "scorecard.json"),
            "--html",
            str(out),
            "--badge",
            str(badge),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert b"\r\n" not in out.read_bytes()
    ET.fromstring(badge.read_text(encoding="utf-8"))


def test_legacy_defense_evasion_tactic_still_renders(repo_root):
    rules = load_rules(repo_root / "rules" / "sigma")
    card = build_scorecard(
        [_scenario("old", "T1070.003", "defense-evasion", 2)],
        [_result("old", ScenarioStatus.PASSED, fired=True, hits=1, evaluated=1)],
        rules,
    )
    columns, empty = tactic_columns(card)
    assert [c.label for c in columns] == ["Defense Evasion (ATT&CK v18 and earlier)"]
    assert "Stealth" in empty


def test_tactic_list_matches_attack_v20_matrix(repo_root):
    import json

    from tripline.report import TACTICS

    data = json.loads((repo_root / "docs" / "attack-v20.1-subset.json").read_text("utf-8"))
    assert [(t["shortname"], t["name"]) for t in data["tactics_matrix_order"]] == TACTICS


def test_report_html_has_benign_and_robustness_sections(repo_root):
    from tripline.benign import load_corpus, replay_benign
    from tripline.cli import _extras
    from tripline.scenarios import load_scenarios

    rules = load_rules(repo_root / "rules" / "sigma")
    scenarios = load_scenarios(repo_root / "scenarios")
    card = build_scorecard(
        [_scenario("a", "T1685.002", "defense-impairment", 3)],
        [_result("a", ScenarioStatus.PASSED, fired=True, hits=1, evaluated=4)],
        rules,
        **_extras(repo_root, rules, scenarios),
    )
    assert card.benign is not None and load_corpus(repo_root / "fixtures" / "benign")
    assert replay_benign(rules, []).events == 0
    html = render_html(card)
    assert "False positives on the benign corpus" in html and "Evasion sweep" in html
    assert "False positives, benign corpus" in html
