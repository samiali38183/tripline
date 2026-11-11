"""Evasion sweep: determinism, controls, and the gaps that are documented rather than hidden."""

from __future__ import annotations

from pathlib import Path

import pytest

from tripline.cli import _load
from tripline.replay import load_fixture_events
from tripline.robustness import (
    GENERATORS,
    SEED,
    family_table,
    run_sweep,
    templates_from,
)

SETUID = "7f3c2b1a-6d4e-4a9b-9c8d-1e2f3a4b5c6d"
UPSTREAM_SETUID = "c21c4eaa-ba2e-419a-92b2-8371703cbe21"


@pytest.fixture(scope="module")
def report():
    root = Path(__file__).resolve().parent.parent
    scenarios, rules = _load(root)
    return run_sweep(scenarios, rules, root)


def _by_id(report):
    return {s.scenario_id: s for s in report.scenarios}


def test_sweep_covers_the_three_linux_scenarios(report):
    assert set(_by_id(report)) == set(GENERATORS)
    assert report.seed == SEED


def test_sweep_is_deterministic(repo_root):
    scenarios, rules = _load(repo_root)
    first = run_sweep(scenarios, rules, repo_root).model_dump_json()
    second = run_sweep(scenarios, rules, repo_root).model_dump_json()
    assert first == second


def test_atomic_base_commands_are_caught(report):
    """Controls: the command each Atomic test runs must be caught, or the sweep is meaningless."""
    controls = {
        "t1548-001-setuid-setgid": "chmod u+xs /tmp/evilBinary",
        "t1070-003-clear-command-history": "rm /root/.bash_history",
        "t1053-003-cron-persistence": "crontab /tmp/persistevil",
    }
    for scenario_id, label in controls.items():
        scenario = _by_id(report)[scenario_id]
        match = next(
            v
            for v in scenario.variants
            if v.label == label or v.label == f"chmod u+xs {label.split()[-1]}"
        )
        assert any(hit is True for hit in match.caught.values()), (scenario_id, label)


def test_setuid_rule_catches_all_cmdline_variants_but_the_documented_ones(report):
    scenario = _by_id(report)["t1548-001-setuid-setgid"]
    missed = {v.label for v in scenario.variants if v.kind == "cmdline" and not v.caught[SETUID]}
    assert missed == {
        "chmod u+s /usr/share/doc/evil/bin",  # the /usr/share/doc exemption
        "cp /bin/chmod /tmp/.c; /tmp/.c u+s f",  # renamed binary: Image no longer says chmod
    }
    busybox = next(v for v in scenario.variants if v.family == "multicall-binary")
    assert busybox.caught[SETUID] is True


def test_upstream_setuid_rule_catches_none_of_the_variants(report):
    scenario = _by_id(report)["t1548-001-setuid-setgid"]
    rule = next(r for r in scenario.rules if r.rule_id == UPSTREAM_SETUID)
    assert not rule.expected and rule.cmdline_caught == 0 and rule.cmdline_variants > 100


def test_not_applicable_is_not_counted_as_a_miss(report):
    cron = _by_id(report)["t1053-003-cron-persistence"]
    crontab = next(v for v in cron.variants if v.family == "crontab-invocation")
    assert None in crontab.caught.values()  # the file-event rule never applies to a process
    for rule in cron.rules:
        assert rule.cmdline_variants < len(cron.variants)


def test_family_table_any_column(report):
    scenario = _by_id(report)["t1070-003-clear-command-history"]
    expected = [r.rule_id for r in scenario.rules if r.expected]
    table = family_table(scenario, expected)
    assert table["rm-binary-and-flags"]["any"] == (21, 21)
    caught, total = table["shell-builtin"]["any"]
    assert 0 < caught < total


def test_templates_need_an_execve_event(repo_root):
    assert templates_from([{"type": "PATH"}]) is None
    scenarios, _ = _load(repo_root)
    cron = next(s for s in scenarios if s.id == "t1053-003-cron-persistence")
    templates = templates_from(load_fixture_events(cron, repo_root))
    assert templates is not None and templates.file is not None
