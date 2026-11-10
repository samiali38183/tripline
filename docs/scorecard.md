# Scorecard

**Gate:** passed - 7 passed, 0 failed, 7 pending of 14 scenarios; 22 expected rules.
**Prevalence-weighted coverage:** 47% of all scenarios, 100% of scenarios with fixtures.

| Scenario | Technique | Plane | Weight | Status | Rules fired | Events |
|---|---|---|---|---|---|---|
| t1003-001-lsass-memory-dump | T1003.001 | windows | 3 | PENDING (fixtures pending) | 0/2 | 0 |
| t1027-obfuscated-powershell-oneliner | T1027 | windows | 1 | PENDING (fixtures pending) | 0/1 | 0 |
| t1047-wmic-process-call-create | T1047 | windows | 4 | PENDING (fixtures pending) | 0/1 | 0 |
| t1053-003-cron-persistence | T1053.003 | linux | 2 | PASS | 2/2 | 42 |
| t1053-005-scheduled-task-persistence | T1053.005 | windows | 2 | PENDING (fixtures pending) | 0/2 | 0 |
| t1059-001-powershell-encoded-download | T1059.001 | windows | 9 | PENDING (fixtures pending) | 0/2 | 0 |
| t1059-003-cmd-suspicious-redirect | T1059.003 | windows | 8 | PENDING (fixtures pending) | 0/1 | 0 |
| t1070-003-clear-command-history | T1070.003 | linux | 2 | PASS | 2/2 | 38 |
| t1078-004-console-login-without-mfa | T1078.004 | aws | 10 | PASS | 2/2 | 7 |
| t1098-001-iam-backdoor-access-key | T1098.001 | aws | 3 | PASS | 1/1 | 1 |
| t1105-certutil-bitsadmin-download | T1105 | windows | 6 | PENDING (fixtures pending) | 0/2 | 0 |
| t1530-s3-bucket-exposure | T1530 | aws | 7 | PASS | 2/2 | 10 |
| t1548-001-setuid-setgid | T1548.001 | linux | 2 | PASS | 1/1 | 84 |
| t1562-008-cloudtrail-stop | T1562.008 | aws | 3 | PASS | 1/1 | 1 |

_tripline 0.2.1, generated 2026-11-10 23:04 UTC_
