# Changelog

## 0.2.1 - 2026-11-10

Fixes from a code review. Each item was reproduced with a failing test first.

### Engine and scoring

* Timestamp part modifiers (`eventTime|minute`, `|hour`, `|day`, `|week`, `|month`, `|year`) now
  evaluate against an ISO 8601 timestamp. Before, they compiled and never matched, which
  contradicted the compiler's rule that unsupported constructs raise `UnsupportedRuleError`; an
  unknown part now raises it.
* A rule with no applicable events is reported as `no applicable events ... (routing problem, not
  a detection miss)` instead of `0 of 0 applicable events matched`. `scorecard.json` gains
  `outcome` on each rule evidence entry (`matched`, `missed`, `no_applicable_events`, `error`,
  `pending`); older scorecards still load and the value is derived. CLI, JUnit, Markdown, gate
  failure text and the HTML report use the new wording.

### Collectors

* The Linux and Windows marker slicers only honour markers that carry the run GUID passed to
  `collect`. A marker from another run in the same log or export is ignored, so it can no longer
  open or close a window, and a window left open by an earlier run no longer leaks events into
  the current one. `slice_by_markers` now requires `run_guid`.

### Rules

* `tripline_lnx_chmod_setuid_setgid_any_form.yml`: now matches `3755`, `5755` and leading-zero
  octal modes (`04755`), symbolic mode lists such as `g+w,u+s`, and a full-path `chmod`. The
  `/usr/share/doc/` exclusion applies only when every file operand is under that directory and
  none contains `..`; appending that path to another target no longer suppresses the event.
  Result on the recorded fixture is unchanged (2 of 36). Details in `docs/findings.md` F-001.
* Two Windows rules for the gaps in F-003: `tripline_win_cmd_redirect_relative_in_suspicious_cwd.yml`
  (T1059.003) and `tripline_win_security_scheduled_task_interpreter_action.yml` (T1053.005). They
  are tested on synthetic events only (`tests/test_windows_rules.py`), are not expected by any
  scenario, and all Windows scenarios remain pending.

### Numbers

* 186 tests (was 113), 89 % line+branch coverage. Scorecard totals unchanged: 7 passed, 0 failed,
  7 pending, 47 % weighted. 26 rules compiled (was 24).

## 0.2.0 - 2026-11-10

### Reporting

* `tripline report scorecard.json --html report.html --badge coverage.svg`: one self-contained
  HTML file (inline CSS, no JavaScript, no CDN) with headline numbers, prevalence weight points by
  status, an ATT&CK-style matrix of scenarios by tactic (pass / fail / pending, weight, rules
  fired, per-rule `hits/applicable` evidence) and a scenario table. Light and dark mode.
  Optional flat SVG badge of weighted coverage.
* `scorecard.json` now records each scenario's `tactic` and per-rule `evidence` (hits, applicable
  events, error). Both default to empty, so older scorecards still load.
* `.github/workflows/pages.yml`: builds the report from a fresh replay of `main` and uploads it as
  an artifact; deploys to GitHub Pages only when the repository variable `PAGES_ENABLED` is
  `true`. `ci.yml` is unchanged and does not depend on it.
* Committed `docs/report.html`, `docs/coverage.svg` and `docs/img/report.png` (README).
* 9 new tests (`tests/test_report.py`): 113 tests, 89 % line+branch coverage.

### Windows plane

* `scripts/windows/Export-TriplineEvents.ps1`, `tripline windows collect --replay` and the
  `emulate-windows` workflow (Sysmon, Security 4688/4698, PowerShell 4104); `tripline atomics
  <plane>` lists the Atomic tests the emulation workflows run.
* `emulate-windows.yml` fixes from the failed scheduled run 42658659666 (finding F-003): the
  Sysmon config now logs ProcessAccess to `lsass.exe` (the SwiftOnSecurity config logs none), the
  WMIC optional feature is installed on the Server 2025 image, AtomicTestHarnesses is installed
  from Windows PowerShell, and the atomics run under `shell: powershell`. Not yet re-run.
* `docs/findings.md` F-003: why 6 of 7 Windows scenarios failed, split into runner problems
  (fixed above) and rule/atomic mismatches that still need a scenario decision.

### Linux plane (Phase A2)

* `tripline/linux/collect.py`: auditd log parser (records merged by serial, EXECVE hex decoding,
  chunked-argument joining, `TargetFilename` from PATH CREATE), tripline marker slicing, per-scenario
  fixture + manifest writer. `tripline linux collect --require-all --replay`.
* `.github/workflows/emulate-linux.yml`: auditd + Invoke-AtomicRedTeam on `ubuntu-latest`,
  weekly + manual; red when an expected rule stops firing on fresh atomics.
* Recorded fixtures for T1053.003, T1070.003, T1548.001 (3/3 pass); scorecard 7/14, weighted 47 %.
* Logsource router: Linux `file_event` category for audit PATH CREATE records.
* New rule `tripline_lnx_chmod_setuid_setgid_any_form` closing finding F-001 (SigmaHQ 'Setuid and
  Setgid' misses `chmod u+xs`). `docs/findings.md` started.

## 0.1.0 - Phase A1 (2026-11-04)

First release: container-free detection gate with a real cloud plane.

* Sigma compiler over pySigma's condition tree (`contains`/`startswith`/`endswith`/`all`, `re`
  with flags, `windash`, `base64offset`, `cidr`, `fieldref`, `exists`, null, comparisons,
  wildcards; `and`/`or`/`not`/parens, `1 of`/`all of`, keywords). Unsupported features raise.
* Logsource router for Fluent Bit `winlog` and `Get-WinEvent | ConvertTo-Json` Windows shapes
  (Sysmon, Security, PowerShell), auditd, CloudTrail.
* Strict pydantic scenario schema; 14 scenarios from the design table (4 AWS, 7 Windows, 3 Linux)
  with real Atomic Red Team test GUIDs.
* Cloud plane: recipes over Stratus Red Team detonation logs and the flaws.cloud dataset,
  timestamp rebase + run GUID, 4 committed fixtures with manifests; all 4 AWS scenarios pass.
* Scorer: per-rule / per-scenario / prevalence-weighted per-technique coverage, `scorecard.json`,
  JUnit XML, Markdown; ATT&CK Navigator v4.5 layer with grey known-gap cells.
* CLI: `validate`, `replay [--all|SCENARIO]`, `score`, `heatmap`, `docs`, `cloud build`.
* CI: ruff, mypy strict, pytest (94 tests, 90 % coverage), `sigma check`, replay gate, JUnit
  artifacts, PR scorecard comment. Gate proven by PR #1 (`docs/gate-proof.md`).
