# Related work

tripline is not the first tool to test detection rules against recorded or generated telemetry.
This page says what already exists, where tripline overlaps, and what it adds. Sources were read
on 2026-11-11; the descriptions below are summaries, not quotations.

| Tool | What it does | Needs | Overlap with tripline | Source |
|---|---|---|---|---|
| SigmaHQ regression tests | Rules with status `test` or `stable` must point at an `info.yml` and event samples (EVTX, JSON, NDJSON); a runner executes on every push and PR and fails when a sample yields fewer than `match_count` matches. | Nothing live; replays samples. | Same core mechanic: replay recorded events through a rule in CI and assert it fires. Per-rule, authored upstream, no technique scoring. | <https://github.com/SigmaHQ/sigma/tree/master/regression_data> |
| rsigma `rule backtest` | Replays a corpus (NDJSON, EVTX) against rules, checks per-rule `exactly` / `at_least` / `at_most` expectations, emits JSON and JUnit, and treats a rule that fires without an expectation as a possible false positive (`--unexpected fail`). | A corpus and an expectations file. | Replay plus expectations plus JUnit, and the benign-corpus idea. Generic engine, no ATT&CK scenario or weighting. | <https://rsigma.io/cli/rule/backtest/> |
| SCYTHE Sigma regression pipeline | Ties each Sigma rule to an Atomic Red Team test; CI converts the rule to SPL, runs the atomic, queries Splunk, fails the merge when nothing returns. Reports per-technique pass/fail/no-coverage. | A Splunk instance and a host that runs the atomic. | Same goal (rule fires on the technique's telemetry) with live execution instead of recorded telemetry. | <https://scythe.io/sigma> |
| Splunk `attack_data` and `attack_range` | Curated datasets recorded from Atomic Red Team runs, organised by technique, replayable into Splunk to test Splunk's detection library. | Splunk for replay; Git LFS (9 GB+). | Same recorded-from-an-atomic idea, Splunk-specific detections. | <https://github.com/splunk/attack_data> |

Not read for this page and therefore not characterised here: Datadog Threatest, Elastic
detection-rules unit tests, Prelude Operator, AMIDES (Sigma evasion research).

## What tripline adds

A small, self-contained gate for a consumer repo: scenarios (technique, tactic, expected rules,
fixtures) live next to the rules, the evaluator is plain Python over NDJSON so it runs offline on
a stock runner in seconds, and the output is a scorecard with prevalence-weighted coverage, a
Navigator layer, an HTML report and a JUnit file. It also publishes findings from using it, such
as the SigmaHQ *Setuid and Setgid* rule matching 0 of 36 events recorded from Atomic Red Team's
own T1548.001 tests ([F-001](findings.md)). Since 0.3.0 it also replays all rules against a
benign corpus and sweeps command-line variants.

## What it does not do

* It is not a replacement for SigmaHQ regression data, rsigma or SCYTHE. Several of them cover
  ground tripline does not (EVTX input, backend-native execution, live SIEM validation).
* It evaluates rules with its own compiler, not a production backend, so a pass is necessary and
  not sufficient ([limitations](limitations.md)).
* It does not execute attacks on your behalf outside the two `emulate-*` workflows, and the
  fixtures are small (14 scenarios).
