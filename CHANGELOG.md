# Changelog

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
