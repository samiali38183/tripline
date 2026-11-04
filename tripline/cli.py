"""``tripline`` command line interface.

Every command works from a repository checkout and nothing else: no SIEM, no containers.
Exit codes are the contract with CI - ``replay`` and ``score`` exit 1 when the gate fails.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from tripline import __version__
from tripline.engine.rules import RuleSet, load_rules
from tripline.events import write_text_lf
from tripline.heatmap import write_layer
from tripline.models import Plane, ReplayResult, Scenario, ScenarioStatus, Scorecard
from tripline.replay import replay_all, replay_scenario
from tripline.scenarios import ScenarioLoadError, load_scenarios, validate_fixture_paths
from tripline.scorer import build_scorecard, read_scorecard, write_junit, write_scorecard

app = typer.Typer(
    name="tripline",
    help="Detection quality gate: replay ATT&CK telemetry through Sigma rules and score it.",
    no_args_is_help=True,
    add_completion=False,
)
cloud_app = typer.Typer(help="AWS plane: build fixtures from public CloudTrail datasets.")
app.add_typer(cloud_app, name="cloud")
linux_app = typer.Typer(help="Linux plane: turn an auditd log from an emulation run into fixtures.")
app.add_typer(linux_app, name="linux")
windows_app = typer.Typer(help="Windows plane: turn exported winlog NDJSON into fixtures.")
app.add_typer(windows_app, name="windows")

RootOpt = Annotated[
    Path, typer.Option("--root", help="Repository root (contains scenarios/, rules/, fixtures/).")
]
STATUS_MARK = {
    ScenarioStatus.PASSED: "PASS",
    ScenarioStatus.FAILED: "FAIL",
    ScenarioStatus.PENDING: "PENDING",
}


def _version(value: bool) -> None:
    if value:
        typer.echo(f"tripline {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """Detection quality gate for Sigma rules."""


def _load(root: Path) -> tuple[list[Scenario], RuleSet]:
    try:
        scenarios = load_scenarios(root / "scenarios")
    except ScenarioLoadError as exc:
        typer.secho(f"scenario error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc
    rules = load_rules(root / "rules" / "sigma")
    return scenarios, rules


@app.command()
def validate(root: RootOpt = Path()) -> None:
    """Validate scenarios, compile every Sigma rule, and check expected rule ids and fixtures."""
    scenarios, rules = _load(root)
    problems = [f"rule {e.path}: {e.reason}" for e in rules.errors]
    problems += validate_fixture_paths(scenarios, root)
    known = rules.ids()
    problems += [
        f"{s.id}: expected rule {rid} is not in rules/sigma"
        for s in scenarios
        for rid in s.expected_rules
        if rid not in known
    ]
    typer.echo(f"{len(scenarios)} scenarios, {len(rules.rules)} rules compiled")
    for problem in problems:
        typer.secho(f"  {problem}", fg=typer.colors.RED)
    if problems:
        raise typer.Exit(code=1)
    typer.secho("ok", fg=typer.colors.GREEN)


@app.command()
def replay(
    scenario: Annotated[str | None, typer.Argument(help="Scenario id to replay.")] = None,
    all_: Annotated[bool, typer.Option("--all", help="Replay every scenario.")] = False,
    root: RootOpt = Path(),
    junit: Annotated[Path | None, typer.Option(help="Write a JUnit XML report here.")] = None,
    scorecard: Annotated[
        Path | None, typer.Option(help="Also write scorecard.json here (same as `score`).")
    ] = None,
    show_events: Annotated[
        bool, typer.Option("--show-events", help="Print the first matching event per rule.")
    ] = False,
) -> None:
    """Replay committed fixtures through expected rules; exit 1 if any expected rule misses."""
    if (scenario is None) == (not all_):
        typer.secho("give exactly one of SCENARIO or --all", err=True, fg=typer.colors.RED)
        raise typer.Exit(code=2)
    scenarios, rules = _load(root)
    if scenario is not None:
        chosen = [s for s in scenarios if s.id == scenario]
        if not chosen:
            typer.secho(f"unknown scenario {scenario!r}", err=True, fg=typer.colors.RED)
            raise typer.Exit(code=2)
        results = [replay_scenario(chosen[0], rules, root)]
    else:
        chosen = scenarios
        results = replay_all(scenarios, rules, root)

    _print_results(chosen, results, show_events=show_events)
    for error in rules.errors:
        typer.secho(f"rule load error: {error.path}: {error.reason}", fg=typer.colors.YELLOW)
    if junit:
        write_junit(results, chosen, junit)
        typer.echo(f"junit written to {junit}")
    if scorecard:
        write_scorecard(build_scorecard(chosen, results, rules), scorecard)
        typer.echo(f"scorecard written to {scorecard}")
    failed = [r for r in results if r.status is ScenarioStatus.FAILED]
    if failed:
        typer.secho(
            f"GATE FAILED: {len(failed)} scenario(s) missed an expected rule: "
            + ", ".join(r.scenario_id for r in failed),
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)
    typer.secho("gate passed", fg=typer.colors.GREEN)


@app.command()
def score(
    root: RootOpt = Path(),
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("scorecard.json"),
    junit: Annotated[Path | None, typer.Option(help="Write a JUnit XML report here.")] = None,
    markdown: Annotated[
        Path | None, typer.Option(help="Write the scorecard as a Markdown table (PR comment).")
    ] = None,
) -> None:
    """Replay everything, write scorecard.json (+ junit/markdown); exit 1 on gate failure."""
    scenarios, rules = _load(root)
    results = replay_all(scenarios, rules, root)
    card = build_scorecard(scenarios, results, rules)
    write_scorecard(card, output)
    typer.echo(f"scorecard written to {output}")
    if junit:
        write_junit(results, scenarios, junit)
    if markdown:
        write_text_lf(markdown, scorecard_markdown(card))
    typer.echo(scorecard_markdown(card))
    if not card.gate.passed:
        raise typer.Exit(code=1)


@app.command()
def heatmap(
    scorecard: Annotated[Path, typer.Argument(help="scorecard.json produced by `score`.")],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("navigator_layer.json"),
) -> None:
    """Render scorecard.json as an ATT&CK Navigator layer (v4.5)."""
    layer = write_layer(read_scorecard(scorecard), output)
    typer.echo(f"{len(layer['techniques'])} technique cells written to {output}")


@app.command()
def docs(
    scorecard: Annotated[Path, typer.Argument(help="scorecard.json produced by `score`.")],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("docs/scorecard.md"),
) -> None:
    """Write the Markdown scorecard page under docs/."""
    card = read_scorecard(scorecard)
    write_text_lf(output, scorecard_markdown(card, heading=True))
    typer.echo(f"written {output}")


@cloud_app.command("build")
def cloud_build(
    root: RootOpt = Path(),
    cache: Annotated[Path, typer.Option(help="Where upstream datasets are downloaded.")] = Path(
        ".cache"
    ),
) -> None:
    """Download public CloudTrail datasets and (re)generate fixtures/cloud/<scenario>/run.ndjson."""
    from tripline.cloud.sources import build_all

    for path in build_all(cache, root / "fixtures" / "cloud"):
        typer.echo(f"wrote {path}")


ReplayOpt = Annotated[
    bool,
    typer.Option(
        "--replay", help="Replay the fresh fixtures through expected rules; exit 1 on a miss."
    ),
]
RequireAllOpt = Annotated[
    bool,
    typer.Option("--require-all", help="Exit 1 if any scenario of the plane produced no events."),
]


def _finish_collect(
    written: dict[str, Path],
    plane: Plane,
    scenarios: list[Scenario],
    rules: RuleSet,
    root: Path,
    *,
    source: str,
    require_all: bool,
    replay_after: bool,
) -> None:
    """Shared tail of the ``<plane> collect`` commands: report, require-all gate, replay gate."""
    from tripline.models import Fixture, Provenance

    for scenario_id, path in written.items():
        typer.echo(f"wrote {path} ({scenario_id})")
    missing = [s.id for s in scenarios if s.plane is plane and s.id not in written]
    for scenario_id in missing:
        typer.secho(f"no events recorded for {scenario_id}", fg=typer.colors.YELLOW)
    if require_all and missing:
        raise typer.Exit(code=1)
    if not replay_after:
        return
    fresh = [
        s.model_copy(
            update={
                "fixtures": [
                    Fixture(
                        path=written[s.id].relative_to(root),
                        provenance=Provenance.RECORDED,
                        source=source,
                    )
                ]
            }
        )
        for s in scenarios
        if s.id in written
    ]
    results = [replay_scenario(s, rules, root) for s in fresh]
    _print_results(fresh, results, show_events=True)
    failed = [r.scenario_id for r in results if r.status is ScenarioStatus.FAILED]
    if failed:
        typer.secho(f"EMULATION GATE FAILED: {', '.join(failed)}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    typer.secho("emulation gate passed", fg=typer.colors.GREEN)


@linux_app.command("collect")
def linux_collect(
    audit_log: Annotated[
        Path, typer.Argument(help="Raw auditd log (audit.log or ausearch --raw).")
    ],
    run_guid: Annotated[str, typer.Option(help="Run GUID used in the tripline-marker commands.")],
    source: Annotated[str, typer.Option(help="Provenance URL (e.g. the workflow run).")],
    root: RootOpt = Path(),
    require_all: RequireAllOpt = False,
    replay_after: ReplayOpt = False,
) -> None:
    """Slice an auditd log by tripline markers into fixtures/linux/<scenario>/run.ndjson."""
    from tripline.linux.collect import collect

    scenarios, rules = _load(root)
    with audit_log.open(encoding="utf-8", errors="replace") as handle:
        written = collect(
            handle, scenarios, root / "fixtures" / "linux", run_guid=run_guid, source=source
        )
    _finish_collect(
        written,
        Plane.LINUX,
        scenarios,
        rules,
        root,
        source=source,
        require_all=require_all,
        replay_after=replay_after,
    )


@windows_app.command("collect")
def windows_collect(
    events_ndjson: Annotated[
        Path, typer.Argument(help="NDJSON from scripts/windows/Export-TriplineEvents.ps1.")
    ],
    run_guid: Annotated[str, typer.Option(help="Run GUID used in the tripline-marker commands.")],
    source: Annotated[str, typer.Option(help="Provenance URL (e.g. the workflow run).")],
    root: RootOpt = Path(),
    require_all: RequireAllOpt = False,
    replay_after: ReplayOpt = False,
) -> None:
    """Slice exported winlog NDJSON by tripline markers into fixtures/windows/<scenario>/."""
    from tripline.events import read_ndjson
    from tripline.windows.collect import collect

    scenarios, rules = _load(root)
    events = read_ndjson(events_ndjson)
    typer.echo(f"{len(events)} events read from {events_ndjson}")
    written = collect(
        events, scenarios, root / "fixtures" / "windows", run_guid=run_guid, source=source
    )
    _finish_collect(
        written,
        Plane.WINDOWS,
        scenarios,
        rules,
        root,
        source=source,
        require_all=require_all,
        replay_after=replay_after,
    )


# --------------------------------------------------------------------------- rendering


def scorecard_markdown(card: Scorecard, *, heading: bool = False) -> str:
    """Render the scorecard as GitHub-flavoured Markdown."""
    t = card.totals
    lines: list[str] = []
    if heading:
        lines += ["# Scorecard", ""]
    gate = "passed" if card.gate.passed else "FAILED"
    scored = (
        f"{t.weighted_coverage_scored:.0%}" if t.weighted_coverage_scored is not None else "n/a"
    )
    lines += [
        f"**Gate:** {gate} - {t.passed} passed, {t.failed} failed, {t.pending} pending "
        f"of {t.scenarios} scenarios; {t.rules} expected rules.",
        f"**Prevalence-weighted coverage:** {t.weighted_coverage:.0%} of all scenarios, "
        f"{scored} of scenarios with fixtures.",
        "",
        "| Scenario | Technique | Plane | Weight | Status | Rules fired | Events |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in card.scenarios:
        fired = f"{len(s.fired_rules)}/{len(s.expected_rules)}"
        status = STATUS_MARK[s.status]
        if s.status is ScenarioStatus.FAILED:
            status += " (" + ", ".join(s.missing_rules) + ")"
        elif s.status is ScenarioStatus.PENDING:
            status += " (fixtures pending)"
        lines.append(
            f"| {s.scenario_id} | {s.technique} | {s.plane.value} | {s.weight} | {status} | "
            f"{fired} | {s.events} |"
        )
    if card.gate.failures:
        lines += ["", "**Failures**", ""] + [f"- {f}" for f in card.gate.failures]
    lines += [
        "",
        f"_tripline {card.tripline_version}, generated {card.generated_at:%Y-%m-%d %H:%M} UTC_",
        "",
    ]
    return "\n".join(lines)


def _print_results(
    scenarios: list[Scenario], results: list[ReplayResult], *, show_events: bool
) -> None:
    by_id = {s.id: s for s in scenarios}
    for result in results:
        scenario = by_id[result.scenario_id]
        colour = {
            ScenarioStatus.PASSED: typer.colors.GREEN,
            ScenarioStatus.FAILED: typer.colors.RED,
            ScenarioStatus.PENDING: typer.colors.YELLOW,
        }[result.status]
        typer.secho(
            f"[{STATUS_MARK[result.status]:>7}] {scenario.id} ({scenario.technique}, "
            f"{scenario.plane.value}) - {result.events} events",
            fg=colour,
        )
        for hit in result.rules:
            mark = "+" if hit.fired else ("~" if result.status is ScenarioStatus.PENDING else "-")
            detail = hit.error or f"{hit.hits}/{hit.evaluated} applicable events"
            typer.echo(f"     {mark} {hit.rule_id}  {hit.title or '?'}  ({detail})")
            if show_events and hit.first_match is not None:
                typer.echo("       " + json.dumps(hit.first_match, sort_keys=True)[:400])


if __name__ == "__main__":  # pragma: no cover
    app()
