# Threat model

What tripline protects, what it trusts, and how it can be abused or fooled. Written for the
repository as it exists; items marked *not mitigated* are real.

## What tripline is

A CI gate for detection content. Inputs are Sigma rules, scenario definitions and recorded
telemetry; the output is a pass/fail verdict plus scorecards. It never touches production hosts.
The only places code executes with privileges are the disposable GitHub-hosted runners used by
`emulate-linux.yml` and `emulate-windows.yml`.

## Assets

| Asset | Why it matters |
|---|---|
| Rule verdicts (`tripline replay --all` exit code) | A wrong *pass* lets a detection regression merge. This is the asset the whole project exists to protect. |
| Committed fixtures (`fixtures/**/run.ndjson`) | They are the ground truth the gate replays. Tampered or stale fixtures silently weaken every verdict. |
| Scorecard / heatmap artifacts | Consumed by humans to decide where to invest; wrong numbers misdirect effort. |
| The repository's CI identity (`GITHUB_TOKEN`) | Could publish or alter artifacts if a workflow were hijacked. |

## Trust boundaries

1. **Pull request author -> CI.** Anyone with write access (or a fork PR, if ever enabled) can
   change rules, scenarios, fixtures and the workflows themselves.
2. **Upstream content -> repository.** SigmaHQ rules, Atomic Red Team tests, Invoke-AtomicRedTeam,
   Sysmon, the SwiftOnSecurity config, Stratus Red Team and flaws.cloud datasets are all fetched
   from the public internet at build or emulation time.
3. **Emulation runner -> artifacts.** Atomics execute as root / Administrator on the runner;
   everything they emit is untrusted data until a maintainer reviews the artifact.
4. **Fixture bytes -> evaluator.** NDJSON is parsed with strict JSON and routed by shape; unknown
   shapes get *no* logsource and are therefore never evaluated.

## Threats and mitigations

### T1. Weakening a scenario to make a failing rule "pass"

*Example:* removing a rule from `expected_rules`, or editing a fixture so the event matches.
*Mitigations:* scenarios and fixtures are reviewed in the same PR as the rule change; CODEOWNERS is
recommended for `scenarios/`, `fixtures/` and `rules/`; `tests/test_replay.py` asserts every
committed fixture matches its `manifest.json` event count and run GUID, so silent edits of one
file without the other fail the unit suite. *Not mitigated:* a reviewer approving a bad change.
The gate makes the weakening visible in the diff; it cannot stop a determined insider.

### T2. Rule that compiles but never evaluates

*Example:* a `condition:` with a typo, or a logsource no fixture satisfies, so the rule returns
"0/0 applicable events" forever. *Mitigations:* `tripline validate` fails CI on rule compile
errors (`RuleLoadError`), the compiler raises `UnsupportedRuleError` on constructs it cannot
evaluate instead of returning `False`, and the replay output prints applicable-event counts so a
0/0 line is visible on every run. *Not mitigated:* a logsource mismatch that leaves a rule with
zero applicable events is reported but does not fail the gate on its own; see Limitations.

### T3. Malicious or compromised upstream content

*Example:* a poisoned Atomic test or installer script runs arbitrary code on the emulation
runner. *Mitigations:* emulation workflows run with `permissions: contents: read`, on ephemeral
hosted runners, with no secrets exposed; they can only upload an artifact. Fixtures are committed
by a human after reading the artifact, never auto-committed. Vendored SigmaHQ rules are copied
with an attribution header and reviewed like any other file. *Not mitigated:* installers are
fetched from `master` branches without pinning; a supply-chain change would be noticed only via
the weekly drift run going red or by artifact review.

### T4. Workflow hijack through PR-controlled files

*Example:* a PR edits `ci.yml` to always exit 0. *Mitigations:* workflow files are visible in the
diff; branch protection on `main` requiring the `detection gate` check is the intended setting
(documented, not enforced by the repository itself). *Not mitigated:* fork PRs are not enabled;
if they were, `pull_request_target` must never be used with checkout of the PR head.

### T5. Fixture provenance laundering

*Example:* a hand-written event labelled `provenance: recorded`. *Mitigations:* the `Fixture`
model requires a `source` URL for `recorded` fixtures; `manifest.json` records the run GUID, time
window and event counts; Linux and Windows events carry a `tripline.run_guid` tag and cloud events
carry it in `userAgent`, and `tests/test_replay.py` checks the tags match the manifest.
*Not mitigated:* nothing cryptographically binds a fixture to a runner. A signed attestation
(`actions/attest-build-provenance`) on the artifact is the natural next step.

### T6. Evaluator divergence from a real SIEM

*Example:* the Python compiler treats a modifier differently from the production backend, so the
gate passes while the SIEM rule misses. *Mitigations:* the compiler walks pySigma's parsed
condition tree rather than re-parsing rules, each modifier has unit tests, and unsupported
features raise. *Not mitigated:* there is no parity test against a real backend yet (OpenSearch
parity is Phase B). Treat tripline's verdict as *necessary*, not *sufficient*, until that lands.

### T7. Secrets and credentials

tripline needs none: cloud fixtures come from public datasets, and emulation runs on hosted
runners with the default token. There are no `.env` files, no cloud keys, and `.gitignore`
excludes `.cache/`. CloudTrail records from flaws.cloud contain the dataset's own (long-dead)
account identifiers, which are part of the published dataset and not a secret of this project.

### T8. Harm from the atomics themselves

Atomics disable logging, dump LSASS, add cron jobs and set setuid bits. *Mitigations:* they run
only on disposable hosted runners that are destroyed after the job; `SECURITY.md` forbids running
them on a workstation; the workflows have no `pull_request` trigger so a PR cannot schedule a
detonation. *Not mitigated:* running the workflows on a self-hosted runner would execute the
atomics on that host — do not register one for this repository.

## Residual risk summary

| Risk | Level | Owner action |
|---|---|---|
| Reviewer approves a weakened scenario | Medium | Add CODEOWNERS + required review on `scenarios/`, `fixtures/`, `rules/` |
| Unpinned upstream installers | Medium | Pin Invoke-AtomicRedTeam / Sysmon versions and checksums |
| No SIEM parity | Medium | Phase B OpenSearch parity test |
| No artifact attestation | Low | `actions/attest-build-provenance` on fixture artifacts |
| Zero-applicable-event rules do not fail the gate | Low | Add `--strict-logsource` flag (tracked in Limitations) |
