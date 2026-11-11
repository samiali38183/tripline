# Scorecard

**Gate:** passed - 13 passed, 0 failed, 1 pending of 14 scenarios; 21 expected rules.
**Prevalence-weighted coverage:** 98% of all scenarios, 100% of scenarios with fixtures.
**Rule provenance:** 98% of weight points have a passing scenario; 52% of weight points pass on unmodified SigmaHQ rules alone (8 scenarios); the other 5 passing scenarios need at least one rule written for this project.

| Scenario | Technique | Plane | Weight | Status | Rules fired | Events |
|---|---|---|---|---|---|---|
| t1003-001-lsass-memory-dump | T1003.001 | windows | 3 | PASS | 2/2 | 70 |
| t1027-obfuscated-powershell-oneliner | T1027 | windows | 1 | PENDING (fixtures pending) | 0/1 | 0 |
| t1047-wmic-process-call-create | T1047 | windows | 4 | PASS | 1/1 | 12 |
| t1053-003-cron-persistence | T1053.003 | linux | 2 | PASS | 2/2 | 42 |
| t1053-005-scheduled-task-persistence | T1053.005 | windows | 2 | PASS | 2/2 | 11 |
| t1059-001-powershell-encoded-download | T1059.001 | windows | 9 | PASS | 1/1 | 154 |
| t1059-003-cmd-suspicious-redirect | T1059.003 | windows | 8 | PASS | 1/1 | 26 |
| t1070-003-clear-command-history | T1070.003 | linux | 2 | PASS | 2/2 | 38 |
| t1078-004-console-login-without-mfa | T1078.004 | aws | 10 | PASS | 2/2 | 7 |
| t1098-001-iam-backdoor-access-key | T1098.001 | aws | 3 | PASS | 1/1 | 1 |
| t1105-certutil-bitsadmin-download | T1105 | windows | 6 | PASS | 2/2 | 33 |
| t1530-s3-bucket-exposure | T1530 | aws | 7 | PASS | 2/2 | 10 |
| t1548-001-setuid-setgid | T1548.001 | linux | 2 | PASS | 1/1 | 84 |
| t1562-008-cloudtrail-stop | T1685.002 | aws | 3 | PASS | 1/1 | 1 |

**False positives on the benign corpus:** 2 false-positive matches from 1 of 6 evaluated rules on 675 benign events (20 of 26 rules had no applicable benign events and were not evaluated).
- New Cron File Created: 2/2 benign events matched (e.g. `/etc/cron.daily/chkrootkit.dpkg-new`)

**Evasion sweep:** 200 of 251 command-line variants caught by an expected rule across 3 Linux scenarios; 0 of 4 alternative-tool variants.
- t1053-003-cron-persistence: Scheduled Cron Task/Job - Linux: 12/24 command-line variants
- t1053-003-cron-persistence: New Cron File Created: 11/16 command-line variants
- t1070-003-clear-command-history: Linux Command History Tampering: 69/103 command-line variants
- t1070-003-clear-command-history: History File Deletion: 34/103 command-line variants
- t1548-001-setuid-setgid: Setuid or Setgid Bit Set via Chmod (Any Mode Form): 106/108 command-line variants

_tripline 0.3.0, generated 2026-11-11 21:08 UTC_
