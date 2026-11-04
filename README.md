# tripline

[![ci](https://github.com/samiali38183/tripline/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/tripline/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![python](https://img.shields.io/badge/python-3.12-blue)

I built tripline because I wanted a way to know whether my detections actually work, not just
how many I have. You write a scenario that says "this ATT&CK technique, emulated this way, should
trigger these Sigma rules." tripline replays the recorded logs through the rules and fails the build
if a rule that should fire doesn't. It runs in GitHub Actions, so a rule change that breaks a
detection shows up as a red PR.

No SIEM needed. The Sigma rules get compiled into plain Python checks and run against log files
committed to the repo.

## What works right now

- **AWS (CloudTrail):** 4 of 4 scenarios pass, using public CloudTrail recordings from Stratus Red
  Team and flaws.cloud.
- **Linux (auditd):** 3 of 3 scenarios pass. A GitHub runner runs the Atomic Red Team tests with
  auditd on, and the logs get saved as test fixtures.
- **Windows (Sysmon / Security / PowerShell):** 7 scenarios written, waiting on the Windows runner
  workflow. They show as *pending* for now.

Coverage is weighted by how common each technique is in the wild, so missing a top technique costs
more than missing a rare one. Current weighted coverage: 47% overall, 100% of the scenarios that have
logs. The scorecard also exports an ATT&CK Navigator layer: [`docs/navigator_layer.json`](docs/navigator_layer.json).

## Something it caught

On the first Linux run, the stock SigmaHQ *Setuid and Setgid* rule matched 0 of 36 events. The rule
looks for the literal text ` chmod u+s`, but the Atomic test ran `chmod u+xs`, and the rule also
misses forms like `chmod 4755`. I wrote a replacement rule that matches any setuid/setgid chmod form.
Details: [`docs/findings.md`](docs/findings.md).

## Quick start

```bash
git clone https://github.com/samiali38183/tripline && cd tripline
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .

tripline validate                                     # scenarios + rules + fixtures consistent?
tripline replay --all                                 # the gate: exit 1 if an expected rule misses
tripline replay t1530-s3-bucket-exposure --show-events
tripline score -o docs/scorecard.json --junit junit.xml --markdown scorecard.md
tripline heatmap docs/scorecard.json -o docs/navigator_layer.json   # ATT&CK Navigator layer v4.5
tripline docs docs/scorecard.json                                   # Markdown scorecard page
```

Output of `tripline replay --all` (trimmed):

```
[   PASS] t1078-004-console-login-without-mfa (T1078.004, aws) - 7 events
     + 3b1f0d2e-7c4a-4d5b-9e8f-2a6c1d0b9f41  AWS Console Login Without MFA  (1/7 applicable events)
     + 8ad1600d-e9dc-4251-b0ee-a65268f29add  AWS Root Credentials  (6/7 applicable events)
[   PASS] t1098-001-iam-backdoor-access-key (T1098.001, aws) - 1 events
     + 0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2  AWS IAM Backdoor Users Keys  (1/1 applicable events)
[PENDING] t1105-certutil-bitsadmin-download (T1105, windows) - 0 events
[   PASS] t1530-s3-bucket-exposure (T1530, aws) - 10 events
     + 8f6a2c41-5d7e-4b0a-a3c9-1e2f3d4c5b6a  AWS S3 Bucket Made Public via ACL or Bucket Policy  (6/10 applicable events)
     + 5c0d9e7b-3a21-4f68-b8d4-7e9f0a1b2c3d  AWS S3 Bucket Enumeration by IAM User from Non-AWS Tooling  (4/10 applicable events)
[   PASS] t1562-008-cloudtrail-stop (T1562.008, aws) - 1 events
     + 4db60cc0-36fb-42b7-9b58-a5b53019fb74  AWS CloudTrail Important Change  (1/1 applicable events)
gate passed
```

To rebuild the cloud fixtures from the public datasets, run `tripline cloud build` (about 450 MB download). Sources are listed in [`fixtures/cloud/SOURCES.md`](fixtures/cloud/SOURCES.md).

## Scenarios

| Plane | Technique | Emulation | Weight |
|---|---|---|---|
| AWS | T1078.004 Cloud Accounts - console login without MFA | Stratus detonation + flaws.cloud replay | 10 |
| AWS | T1530 Data from Cloud Storage - S3 made public, enumerated | flaws.cloud replay | 7 |
| AWS | T1562.008 Impair Defenses - CloudTrail StopLogging | Stratus detonation replay | 3 |
| AWS | T1098.001 Additional Cloud Credentials - IAM backdoor key | Stratus detonation replay | 3 |
| Win | T1059.001 PowerShell - encoded command + download cradle | ART `0d181431`, `cc50fa2a` | 9 |
| Win | T1059.003 Command Shell - suspicious output redirect | ART `d0eb3597`, `00682c9f` | 8 |
| Win | T1105 Ingress Tool Transfer - certutil / bitsadmin | ART `dd3b61dd`, `a1921cd3` | 6 |
| Win | T1047 WMI - `wmic process call create` | ART `b3bdfc91` | 4 |
| Win | T1027 Obfuscated PowerShell one-liner | ART `8b3f4ed6`, `6683baf0` | 1 |
| Win | T1003.001 LSASS Memory - comsvcs MiniDump | ART `2536dee2` | 3 |
| Win | T1053.005 Scheduled Task persistence | ART `42f53695` | 2 |
| Linux | T1053.003 Cron persistence | ART `078e69eb`, `435057fb` | 2 |
| Linux | T1070.003 Clear Command History | ART `a934276e`, `b1251c35` | 2 |
| Linux | T1548.001 Setuid / Setgid | ART `759055b3`, `db55f666` | 2 |

Weight is based on how common the technique is in Red Canary's 2026 Threat Detection Report (10 = most common).

## How it works

1. **Scenarios** (`scenarios/*.yaml`): technique, how it's emulated, which rules should fire, and a weight.
2. **Compiler** (`tripline/engine/compiler.py`): uses pySigma to parse each rule and turns the
   condition into a Python function. If a rule uses something it can't handle, it errors out instead
   of quietly returning no match.
3. **Log routing** (`tripline/logsource.py`): only checks a rule against the log type it's written
   for (Sysmon, Security, PowerShell, auditd, CloudTrail), so a rule with 0 matching events is easy to spot.
4. **Replay and scoring** (`tripline/replay.py`, `tripline/scorer.py`): hit counts per rule,
   pass/fail per scenario, weighted coverage per technique. Outputs `scorecard.json` and JUnit XML
   for GitHub.

For Linux, each Atomic test runs between two marker commands so the audit log can be sliced per
test. See [`.github/workflows/emulate-linux.yml`](.github/workflows/emulate-linux.yml).

Tests: `pytest --cov=tripline` (100 tests, about 89% coverage). Also checked with ruff, mypy and
`sigma check`.

## Next

- Windows runner workflow so the 7 pending scenarios get real logs
- Evasion variants (casing, encoding, argument order) to test how robust each rule is
- A benign log set to measure false positives

## Limitations

See [`docs/limitations.md`](docs/limitations.md) and [`docs/threat-model.md`](docs/threat-model.md).
Only run the Atomic tests on throwaway machines; see [`SECURITY.md`](SECURITY.md).

## License

MIT for the code. The SigmaHQ rules included here are under the Detection Rule License 1.1
([`rules/sigma/LICENSE-DRL.md`](rules/sigma/LICENSE-DRL.md)).
