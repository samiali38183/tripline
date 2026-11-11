# Security policy

## What this repository does

tripline runs **adversary emulation** (Atomic Red Team tests, Stratus Red Team detonation
replays) and evaluates Sigma rules against the resulting telemetry. The emulation side is
intentionally hostile to the host it runs on.

## Where atomics may run

* Atomic Red Team tests are executed **only** on ephemeral GitHub Actions runners or in a
  disposable VM you own and will destroy afterwards. Never run `scenarios/*.yaml` atomics on a
  workstation, a shared host, or anything joined to a production directory.
* The cloud plane never touches a live AWS account. All CloudTrail telemetry is replayed from
  public datasets (`fixtures/cloud/SOURCES.md`); `tripline` holds no cloud credentials.
* `tripline replay`, `score`, `heatmap` and `docs` are pure file-in/file-out and safe anywhere.

## Secrets

No credentials, tokens or private telemetry belong in this repository. Fixtures are built from
published datasets whose authors released them for analysis; if you contribute fixtures from your
own environment, scrub account ids, ARNs, hostnames and usernames first.

## Reporting a vulnerability

Open a private security advisory on GitHub (Security > Advisories > Report a vulnerability) or
email samiali38183@gmail.com. Please include the commit hash and reproduction steps. You will get
an acknowledgement within 72 hours.

