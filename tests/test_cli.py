"""CLI tests via typer's CliRunner against the committed repository and a broken copy."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tripline.cli import app, scorecard_markdown
from tripline.scorer import read_scorecard

runner = CliRunner()
CLOUD_RULE = Path("rules/sigma/cloud/tripline_aws_console_login_without_mfa.yml")


def _run(*args: str, root: Path):
    return runner.invoke(app, [*args, "--root", str(root)] if "--root" not in args else list(args))


@pytest.fixture
def broken_repo(repo_root, tmp_path) -> Path:
    """Copy of scenarios/rules/fixtures with one cloud rule's condition made unsatisfiable.

    The same edit is used by the gate-proof PR (docs/gate-proof.md).
    """
    for folder in ("scenarios", "rules", "fixtures"):
        shutil.copytree(repo_root / folder, tmp_path / folder)
    rule = tmp_path / CLOUD_RULE
    rule.write_text(
        rule.read_text(encoding="utf-8").replace(
            "additionalEventData.MFAUsed: 'No'", "additionalEventData.MFAUsed: 'Maybe'"
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and result.output.startswith("tripline ")


def test_validate_ok(repo_root):
    result = _run("validate", root=repo_root)
    assert result.exit_code == 0, result.output
    assert "14 scenarios" in result.output and "ok" in result.output


def test_validate_reports_unknown_rule(repo_root, tmp_path):
    for folder in ("scenarios", "rules", "fixtures"):
        shutil.copytree(repo_root / folder, tmp_path / folder)
    scenario = tmp_path / "scenarios" / "t1562-008-cloudtrail-stop.yaml"
    text = scenario.read_text(encoding="utf-8").replace(
        "expected_rules:\n", "expected_rules:\n  - 99999999-9999-4999-8999-999999999999\n"
    )
    scenario.write_text(text, encoding="utf-8")
    result = _run("validate", root=tmp_path)
    assert (
        result.exit_code == 1
        and "99999999-9999-4999-8999-999999999999 is not in rules/sigma" in result.output
    )


def test_validate_reports_bad_scenario(repo_root, tmp_path):
    shutil.copytree(repo_root / "rules", tmp_path / "rules")
    (tmp_path / "scenarios").mkdir()
    (tmp_path / "scenarios" / "x.yaml").write_text("id: 1\n", encoding="utf-8")
    result = _run("validate", root=tmp_path)
    assert result.exit_code == 2 and "scenario error" in result.output


def test_replay_all_passes_on_committed_repo(repo_root, tmp_path):
    result = _run(
        "replay", "--all", "--junit", str(tmp_path / "j.xml"), "--show-events", root=repo_root
    )
    assert result.exit_code == 0, result.output
    assert "gate passed" in result.output
    assert result.output.count("[   PASS]") == 13 and result.output.count("[PENDING]") == 1
    assert "t1078-004-console-login-without-mfa (T1078.004, aws) - 7 events" in result.output
    assert (tmp_path / "j.xml").exists()


def test_replay_single_scenario(repo_root):
    result = _run("replay", "t1562-008-cloudtrail-stop", root=repo_root)
    assert (
        result.exit_code == 0
        and "StopLogging" not in result.output
        and "[   PASS]" in result.output
    )


def test_replay_argument_validation(repo_root):
    assert _run("replay", root=repo_root).exit_code == 2
    assert _run("replay", "--all", "t1562-008-cloudtrail-stop", root=repo_root).exit_code == 2
    assert _run("replay", "nope", root=repo_root).exit_code == 2


def test_replay_gate_fails_and_names_scenario(broken_repo):
    result = _run("replay", "--all", root=broken_repo)
    assert result.exit_code == 1
    assert "GATE FAILED" in result.output and "t1078-004-console-login-without-mfa" in result.output
    assert "[   FAIL]" in result.output


def test_score_writes_artifacts_and_markdown(repo_root, tmp_path):
    out = tmp_path / "scorecard.json"
    md = tmp_path / "scorecard.md"
    result = _run(
        "score",
        "-o",
        str(out),
        "--junit",
        str(tmp_path / "j.xml"),
        "--markdown",
        str(md),
        root=repo_root,
    )
    assert result.exit_code == 0, result.output
    card = read_scorecard(out)
    assert card.totals.passed == 13 and card.totals.pending == 1 and card.gate.passed
    text = md.read_text(encoding="utf-8")
    assert (
        "| Scenario |" in text
        and "PENDING (fixtures pending)" in text
        and "**Gate:** passed" in text
    )


def test_score_exit_1_on_broken_rule(broken_repo, tmp_path):
    result = _run("score", "-o", str(tmp_path / "s.json"), root=broken_repo)
    assert result.exit_code == 1
    assert "FAIL (3b1f0d2e-7c4a-4d5b-9e8f-2a6c1d0b9f41)" in result.output


def test_heatmap_and_docs_commands(repo_root, tmp_path):
    card = repo_root / "docs" / "scorecard.json"
    layer = tmp_path / "layer.json"
    assert runner.invoke(app, ["heatmap", str(card), "-o", str(layer)]).exit_code == 0
    assert len(json.loads(layer.read_text(encoding="utf-8"))["techniques"]) == 17
    page = tmp_path / "docs" / "scorecard.md"
    assert runner.invoke(app, ["docs", str(card), "-o", str(page)]).exit_code == 0
    assert page.read_text(encoding="utf-8").startswith("# Scorecard")


def test_markdown_lists_failures(broken_repo, tmp_path):
    out = tmp_path / "s.json"
    _run("score", "-o", str(out), root=broken_repo)
    text = scorecard_markdown(read_scorecard(out))
    assert "**Failures**" in text and "t1078-004-console-login-without-mfa" in text


def test_benign_command_reports_false_positives(repo_root):
    result = _run("benign", root=repo_root)
    assert result.exit_code == 0, result.output
    assert "benign corpus:" in result.output and "false-positive matches" in result.output
    assert _run("benign", "--fail-on-match", root=repo_root).exit_code == 1


def test_benign_command_without_corpus_exits_2(repo_root, tmp_path):
    for folder in ("scenarios", "rules"):
        shutil.copytree(repo_root / folder, tmp_path / folder)
    # scenarios reference fixtures that are absent here; the benign command must still fail cleanly
    result = _run("benign", root=tmp_path)
    assert result.exit_code == 2


def test_robustness_command_writes_json_and_markdown(repo_root, tmp_path):
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    result = runner.invoke(
        app,
        [
            "robustness",
            "--root",
            str(repo_root),
            "--output",
            str(out_json),
            "--markdown",
            str(out_md),
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out_json.read_text("utf-8"))
    assert {s["scenario_id"] for s in data["scenarios"]} == {
        "t1548-001-setuid-setgid",
        "t1070-003-clear-command-history",
        "t1053-003-cron-persistence",
    }
    md = out_md.read_text("utf-8")
    assert "# Evasion sweep" in md and "Variants no expected rule catches" in md


def test_score_includes_benign_and_robustness_sections(repo_root, tmp_path):
    out = tmp_path / "card.json"
    result = runner.invoke(app, ["score", "--root", str(repo_root), "-o", str(out)])
    assert result.exit_code == 0, result.output
    card = read_scorecard(out)
    assert card.benign is not None and card.benign.events > 0
    assert card.robustness is not None and card.robustness.cmdline_total > 0
    text = scorecard_markdown(card)
    assert "False positives on the benign corpus" in text and "Evasion sweep" in text


def test_old_scorecards_without_new_sections_still_load(repo_root, tmp_path):
    out = tmp_path / "card.json"
    runner.invoke(app, ["score", "--root", str(repo_root), "-o", str(out)])
    data = json.loads(out.read_text("utf-8"))
    data.pop("benign"), data.pop("robustness")
    out.write_text(json.dumps(data), encoding="utf-8")
    card = read_scorecard(out)
    assert card.benign is None and card.robustness is None
    assert "False positives" not in scorecard_markdown(card)


def test_provenance_split_matches_rule_authorship(repo_root, tmp_path):
    """Vendored-only coverage is computed from each expected rule's author, not estimated."""
    from tripline.engine.rules import load_rules
    from tripline.scenarios import load_scenarios
    from tripline.scorer import is_authored

    out = tmp_path / "card.json"
    runner.invoke(app, ["score", "--root", str(repo_root), "-o", str(out)])
    card = read_scorecard(out)
    rules = load_rules(repo_root / "rules" / "sigma")
    scenarios = {s.id: s for s in load_scenarios(repo_root / "scenarios")}
    authored = {r.id for r in rules.rules if is_authored(r)}
    assert authored
    vendored_weight = 0
    for s in card.scenarios:
        needs = any(r in authored for r in scenarios[s.scenario_id].expected_rules)
        assert s.needs_authored_rule is needs
        if s.status.value == "passed" and not needs:
            vendored_weight += s.weight
    total = sum(s.weight for s in card.scenarios)
    t = card.totals
    assert t.weighted_coverage_vendored == vendored_weight / total
    assert (t.passed_vendored_only or 0) + (t.passed_needs_authored or 0) == t.passed
    assert t.weighted_coverage_vendored <= t.weighted_coverage
    text = scorecard_markdown(card)
    assert "unmodified SigmaHQ rules alone" in text
    assert "SigmaHQ rules alone" in render_html_for(card)


def render_html_for(card):
    from tripline.report import render_html

    return render_html(card)
