# ATT&CK version used

tripline targets **ATT&CK Enterprise v20** (released 2026-10-13, the version marked current at
<https://attack.mitre.org/resources/updates/> on 2026-11-11). Technique and tactic facts were
taken from the STIX bundle `enterprise-attack-20.1.json` (collection version 20.1, modified
2026-11-05) in <https://github.com/mitre-attack/attack-stix-data>. A subset of that bundle, with
the bundle's SHA-256, is committed as [`attack-v20.1-subset.json`](attack-v20.1-subset.json) and
checked by `tests/test_scenarios.py` and `tests/test_report.py`.

## What changed between v16 (the previous layer) and v20.1 for the 14 scenarios

* **Defense Evasion no longer exists.** v19 (2026-04-28) split it into **Stealth** (TA0005, which
  reuses the old tactic ID) and **Defense Impairment** (TA0112). Enterprise has 15 tactics. The
  report's tactic grid now uses the v20 matrix order.
* **T1562.008 (Disable or Modify Cloud Logs) is revoked** and replaced by **T1685.002 (Disable or
  Modify Cloud Log)**, tactic Defense Impairment. The CloudTrail StopLogging scenario now uses
  T1685.002. The vendored SigmaHQ rule still carries the `attack.t1562.008` tag; vendored rules
  are not edited.
* T1027 and T1070.003 moved from Defense Evasion to **Stealth** (both are now version 2.0).
* T1548.001 (Setuid and Setgid) lost Defense Evasion and is Privilege Escalation only (version
  2.0). The authored setuid rule dropped its `attack.defense-evasion` tag; `sigma check rules/`
  now reports 0 issues instead of 1 medium.
* T1078.004 lists Stealth in place of Defense Evasion (still Initial Access, Persistence,
  Privilege Escalation); the scenario's tactic stays `initial-access`.
* The other techniques keep their IDs and tactics (minor version bumps only).

Navigator layer: `versions.attack` is `20`; the layer format version (4.5) and Navigator version
(5.1.0) fields were not changed and were not checked against a newer Navigator release.

Older scorecards that still say `defense-evasion` render in a separate "Defense Evasion (ATT&CK
v18 and earlier)" column.
