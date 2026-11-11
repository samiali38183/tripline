"""Benign corpus: sanitizer, collector, replay and the committed corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_linux_collect import RUN, _execve, _marker

from tripline.benign import (
    BENIGN_TEST_GUID,
    Sanitizer,
    collect_benign,
    find_secret_patterns,
    load_corpus,
    replay_benign,
)
from tripline.engine.rules import load_rules

SETUID_RULE = "7f3c2b1a-6d4e-4a9b-9c8d-1e2f3a4b5c6d"


def _log(argvs: list[tuple[list[str], str]]) -> list[str]:
    lines = _marker(1, 1700000000.0, BENIGN_TEST_GUID, "start")
    for i, (argv, exe) in enumerate(argvs, start=10):
        lines += _execve(i, 1700000001.0 + i, argv, exe)
    lines += _marker(99, 1700000100.0, BENIGN_TEST_GUID, "end")
    return lines


def test_sanitizer_redacts_secrets_hosts_and_drops_noise() -> None:
    s = Sanitizer(hosts=("fv-az123-45",))
    event = {
        "a1": "https://user:hunter2@example.com/x.git",
        "a2": "token=abc123 ghp_" + "A" * 30,
        "a3": "mail me@corp.com from 8.8.8.8 or 10.1.2.3",
        "a4": "host fv-az123-45 is busy",
        "hostname": "fv-az123-45",
        "paths": [{"name": "/etc/x", "nametype": "NORMAL", "mode": "0100644", "inode": "7"}],
    }
    out = s.event(event)
    text = json.dumps(out)
    assert "hunter2" not in text and "abc123" not in text and "ghp_" not in text
    assert "me@corp.com" not in text and "8.8.8.8" not in text
    assert "10.1.2.3" in text  # private ranges are not personal data
    assert "fv-az123-45" not in text and "hostname" not in out
    assert out["paths"] == [{"name": "/etc/x", "nametype": "NORMAL", "mode": "0100644"}]
    assert s.counts["github_token"] == 1 and s.counts["hostname"] == 1
    assert find_secret_patterns([out]) == []


def test_find_secret_patterns_flags_unsanitized_events() -> None:
    assert find_secret_patterns([{"a0": "password=hunter2"}])


def test_collect_benign_writes_corpus_and_manifest(tmp_path: Path) -> None:
    log = _log([(["chmod", "644", "a.txt"], "/usr/bin/chmod"), (["ls"], "/usr/bin/ls")])
    target = collect_benign(
        log, tmp_path, run_guid=RUN, source="https://example.invalid/run/1", workload="w"
    )
    events = load_corpus(tmp_path)
    assert target.name == "run.ndjson" and len(events) == 2
    manifest = json.loads((tmp_path / "manifest.json").read_text("utf-8"))
    assert manifest["events"] == 2 and manifest["kind"] == "benign"
    assert manifest["bytes"] == target.stat().st_size


def test_collect_benign_errors(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no events"):
        collect_benign([], tmp_path, run_guid=RUN, source="s", workload="w")
    log = _log([(["ls"], "/usr/bin/ls")])
    with pytest.raises(ValueError, match="over the"):
        collect_benign(log, tmp_path, run_guid=RUN, source="s", workload="w", max_bytes=10)
    assert not (tmp_path / "run.ndjson").exists()


def test_replay_benign_reports_false_positives_and_unevaluated(
    tmp_path: Path, repo_root: Path
) -> None:
    log = _log(
        [
            (["chmod", "644", "a.txt"], "/usr/bin/chmod"),
            (["chmod", "g+s", "shared"], "/usr/bin/chmod"),  # a legitimate setgid directory
        ]
    )
    collect_benign(log, tmp_path, run_guid=RUN, source="s", workload="w")
    report = replay_benign(load_rules(repo_root / "rules" / "sigma"), load_corpus(tmp_path))
    by_id = {r.rule_id: r for r in report.rules}
    assert by_id[SETUID_RULE].matched == 1 and by_id[SETUID_RULE].applicable == 2
    assert by_id[SETUID_RULE].examples == ["chmod g+s shared"]
    assert report.total_matches >= 1 and report.events == 2
    # AWS rules have no applicable benign events: not evaluated, not "clean".
    assert any(r.applicable == 0 for r in report.rules)
    assert "false-positive matches" in report.summary()


def test_committed_benign_corpus_is_clean_and_within_budget(repo_root: Path) -> None:
    directory = repo_root / "fixtures" / "benign"
    if not directory.is_dir():
        pytest.skip("no committed benign corpus")
    events = load_corpus(directory)
    assert events, "fixtures/benign exists but holds no events"
    assert sum(p.stat().st_size for p in directory.rglob("*.ndjson")) < 5_000_000
    assert find_secret_patterns(events) == []
    manifest = json.loads((directory / "linux" / "manifest.json").read_text("utf-8"))
    assert manifest["events"] == len(events)


def test_cli_collect_benign_writes_corpus_and_fails_cleanly(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from tripline.cli import app

    audit = tmp_path / "audit.log"
    audit.write_text("\n".join(_log([(["ls", "-l"], "/usr/bin/ls")])) + "\n", encoding="utf-8")
    runner = CliRunner()
    args = ["linux", "collect-benign", str(audit), "--source", "s", "--root", str(tmp_path)]
    ok = runner.invoke(app, [*args, "--run-guid", RUN, "--redact-host", "h"])
    assert ok.exit_code == 0, ok.output
    assert (tmp_path / "fixtures" / "benign" / "linux" / "run.ndjson").exists()
    bad = runner.invoke(app, [*args, "--run-guid", "00000000-0000-4000-8000-000000000000"])
    assert bad.exit_code == 1 and "benign collection failed" in bad.output
