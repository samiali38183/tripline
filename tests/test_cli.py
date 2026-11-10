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
    assert result.output.count("[   PASS]") == 7 and result.output.count("[PENDING]") == 7
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
    assert card.totals.passed == 10 and card.totals.pending == 4 and card.gate.passed
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
