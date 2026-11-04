# tripline

[![ci](https://github.com/samiali38183/tripline/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/tripline/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![python](https://img.shields.io/badge/python-3.12-blue)

**Detection quality gate: emulate ATT&CK techniques in CI, replay telemetry through Sigma rules,
score coverage and robustness, fail PRs on regressions.**

`tripline` treats detections like software. A YAML *scenario* names an ATT&CK technique, an
emulation (an Atomic Red Team test, or a recorded Stratus Red Team / flaws.cloud CloudTrail
detonation), and the Sigma rules expected to fire. `tripline replay` loads the recorded telemetry,
compiles the Sigma rules into Python predicates (no SIEM required), and asserts that every expected
rule fires. The result is a per-rule / per-scenario / per-technique scorecard, weighted by Red
Canary's 2026 technique prevalence so the heatmap answers *"how exposed are we to what actually
happens"*, not *"how many rules do we have"*. The GitHub Action posts the scorecard on the PR and
fails the build when an expected rule stops firing.

Phase A1 shipped the engine, the scorer, the CI gate and a **real cloud plane**: all four AWS
scenarios replay recorded public CloudTrail telemetry and pass. Phase A2 (in progress) records
endpoint telemetry on GitHub runners: the **Linux plane is live** - auditd from `ubuntu-latest`
running the Atomic Red Team tests, 3/3 scenarios pass, and the first run already found a real
SigmaHQ rule gap ([docs/findings.md](docs/findings.md)). Windows scenarios are specified (Atomic
GUIDs, expected rules) and report *pending* until `emulate-windows.yml` lands.

## Architecture

```
  scenarios/*.yaml ──────► 1. PLANNER ──► 2. EMULATOR ─────────► 3. COLLECTOR ──────► 4. EVALUATOR ───► 5. SCORER ──► 6. REPORTER
  (technique, emulation,    strict        ┌ windows: ART on       NDJSON fixtures per   pySigma condition   coverage      ├ scorecard.json
   expected rules,          pydantic      │  win runner  [A2]     scenario, run-GUID    tree → Python       (rule,        ├ junit.xml  (CI gate)
   prevalence weight)       models        ├ linux: ART on         tagged, committed     predicate per       scenario,     ├ navigator_layer.json
                                          │  ubuntu runner [A2]   under fixtures/       logsource field     technique,    ├ docs/scorecard.md
  rules/sigma/**.yml ─────────────────►   └ aws: REPLAY Stratus/  (cloud: done)         map (Sysmon,        prevalence-   └ PR comment (Action)
  (SigmaHQ, DRL 1.1 +                        flaws.cloud records                        Security, PS,       weighted)
   custom cloud rules)                       rebased + GUID                             auditd, CloudTrail)

  Phase B: 7. MUTATOR (evasion variants → robustness)   8. RESPONDER (enrich + auto-close with evidence)   OpenSearch parity backend
```

Everything in Phase A1 runs from a plain checkout: no containers, no cloud account, no SIEM.

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

`tripline replay --all` on this checkout (excerpt; scenarios print in id order):

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

Rebuild the cloud fixtures from upstream (downloads ~450 MB of public CloudTrail into `.cache/`):
`tripline cloud build`. Recipes live in `tripline/cloud/sources.py`; provenance in
[`fixtures/cloud/SOURCES.md`](fixtures/cloud/SOURCES.md).

## Results (from the committed [`docs/scorecard.json`](docs/scorecard.json))

| Plane | Scenarios | Status | Rules fired |
|---|---|---|---|
| AWS CloudTrail | 4 | **4/4 pass** on recorded Stratus Red Team + flaws.cloud telemetry | 6/6 |
| Windows (Sysmon / Security / PowerShell) | 7 | fixtures pending: Phase A2 | 0/11 (pending) |
| Linux (auditd) | 3 | **3/3 pass** on auditd recorded from Atomic Red Team on `ubuntu-latest` ([run](https://github.com/samiali38183/tripline/actions/runs/41838714456)) | 5/5 |

Prevalence-weighted coverage: **47 %** of all 14 scenarios (pending counts as 0), **100 %** of the
scenarios that have fixtures. Full table: [`docs/scorecard.md`](docs/scorecard.md). Navigator
layer with 14 scored cells plus three grey *known gap* cells (T1114.003, T1564.008, T1204.004 -
need a mail tenant or a human at the keyboard): [`docs/navigator_layer.json`](docs/navigator_layer.json).

The gate is proven, not described: [`docs/gate-proof.md`](docs/gate-proof.md) links the PR that
broke one cloud rule's condition and went red naming the scenario.

Test suite: 100 tests, 89 % line coverage (`pytest --cov=tripline`), ruff and `mypy --strict` clean,
`sigma check rules/` clean (24 rules: 20 vendored from SigmaHQ under DRL 1.1, 3 custom CloudTrail
rules, 1 custom Linux rule written to close [finding F-001](docs/findings.md)).

### Linux emulation on GitHub runners

[`.github/workflows/emulate-linux.yml`](.github/workflows/emulate-linux.yml) installs auditd
(`execve` + cron directory watches), installs Invoke-AtomicRedTeam as root, and runs each Linux
atomic between two marker commands (`sh -c "true tripline-marker <run-guid> <test-guid> start|end"`)
so the audit log carries its own attribution. `tripline linux collect audit.log --run-guid ... --replay`
merges audit records by serial (SYSCALL + EXECVE + PATH + CWD + PROCTITLE), hex-decodes arguments,
slices by marker into `fixtures/linux/<scenario>/run.ndjson` + `manifest.json`, and replays the
fresh fixtures through the expected rules - the workflow is red if a rule stops firing on *today's*
atomics. Fixtures are uploaded as an artifact and committed after review.

## Scenarios (DESIGN section 3)

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

Weight = Red Canary 2026 Threat Detection Report prevalence bucket (10 = #1 technique).

## How the engine works

* **Compiler** (`tripline/engine/compiler.py`) walks pySigma's parsed condition tree and emits a
  Python predicate per rule. Supported: `contains`/`startswith`/`endswith`/`all`, `re` (+`i m s`
  flags), `windash`, `base64offset`, `cidr`, `fieldref`, `exists`, null, numeric comparisons,
  wildcards; `and`/`or`/`not`/parentheses, `1 of x*`, `all of x*`, `1 of them`, keyword lists.
  Anything it cannot evaluate raises `UnsupportedRuleError` instead of silently returning `False`.
* **Logsource router** (`tripline/logsource.py`) maps collector shapes to Sigma logsources: Fluent
  Bit `winlog` and `Get-WinEvent | ConvertTo-Json` (both plain and `ToXml()`) for Sysmon, Security
  and PowerShell channels; auditd records (EXECVE normalised to `Image`/`CommandLine`); CloudTrail.
  A rule is only *evaluated* on events whose logsource it declares, so "0 applicable events" is a
  routing bug you see, not a silent pass.
* **Replay / scorer** (`tripline/replay.py`, `tripline/scorer.py`): per-rule hit counts with the
  first matching event, per-scenario pass/fail/pending, per-technique prevalence-weighted
  coverage; `scorecard.json` + JUnit XML so GitHub renders failures natively.
* **Cloud plane** (`tripline/cloud/`): recipes select real records from public datasets, rebase
  `eventTime` preserving offsets, and tag `userAgent` with `tripline/<run-guid>`.

## Roadmap

* **Phase A2 - endpoint emulation on GitHub runners.** Linux done (`emulate-linux.yml`). Next:
  `emulate-windows.yml` (Sysmon + Invoke-Atomic on `windows-latest`, `Get-WinEvent` NDJSON export,
  `tripline windows collect`) so the 7 pending Windows scenarios score for real.
* **Phase B - mutator** (case/quoting/encoding/arg-order/LOLBin substitution/`userAgent` swap
  variants per emulation → robustness score, with the Sigma modifier that saved each rule),
  **responder** (enrich + auto-close with an audit trail), **benign corpora** for precision, and
  an **OpenSearch backend** with a parity test against the Python engine.

## Licence

MIT (code). Vendored SigmaHQ rules: Detection Rule License 1.1, see
[`rules/sigma/LICENSE-DRL.md`](rules/sigma/LICENSE-DRL.md). Atomics run only on disposable hosts -
see [`SECURITY.md`](SECURITY.md).
