# Benign corpus (false-positive measurement)

`fixtures/benign/linux/run.ndjson` holds auditd telemetry recorded while ordinary work ran on a
GitHub-hosted `ubuntu-latest` runner. `tripline benign` replays every compiled rule over it
and reports, per rule, how many benign events matched. A rule that matches is a false positive
on this corpus and is reported, never hidden. The scorecard, the Markdown PR comment and the HTML
report carry the same numbers.

## Provenance

* Recorded by [`emulate-linux.yml`](../.github/workflows/emulate-linux.yml) with input
  `record: benign`, run [43090057704](https://github.com/samiali38183/tripline/actions/runs/43090057704)
  on 2026-11-11. Same auditd rules as the attack recordings (`execve` for both architectures, and
  write/attribute watches on the cron directories), so event shapes match the attack fixtures.
* The workload is [`scripts/linux/benign_workload.sh`](../scripts/linux/benign_workload.sh),
  bracketed by `tripline-marker ... benign start|end` commands exactly like the atomics:
  `apt-get install` of `jq`, `tree` and `chkrootkit` (which writes `/etc/cron.daily/chkrootkit`),
  a Python venv with `pip install requests pytest`, `git init/add/commit/branch/tag/log/diff` and a
  shallow `git clone` of this repository, a small C project built with `make` and a pytest run, `tar`
  and `find`, `chmod` with `644`, `0644`, `755`, `600`, `700`, `440`, `640`, `1777`, `+x`, `u+x`,
  `a+r`, `g+w`, `o-rwx`, `-R go-w`, `-R 755`, `u-s` and full-path `/bin/chmod`, `/usr/bin/chmod`
  (none sets setuid or setgid), reads of cron configuration (`crontab -l`, `ls /etc/cron.d`,
  `cat /etc/crontab`, `run-parts --test`, `logrotate -d`), a shell with `HISTSIZE=5000`, reads
  of `~/.bash_history`, `curl`/`wget` to example.com, `ssh-keygen`, `systemctl`, `journalctl` and
  about 20 seconds of idle loop.
* Size: 675 events (488 `EXECVE`), 752,138 bytes, window 2026-11-11T19:45:16Z to 19:45:49Z
  (about 33 seconds). The budget is 5 MB; a first attempt that also installed `rkhunter` produced
  5.29 MB and was refused by the collector.

## Sanitization

`tripline linux collect-benign` (`tripline/benign.py`) processes every event before anything is
written. What was removed or changed (counts are in `manifest.json`):

* Fields dropped: `hostname`, `node`, `addr`, `terminal`, `exe_hash`. The runner hostname was also
  passed explicitly and replaced where it appeared in text (1 occurrence).
* `paths` entries reduced to `name`, `nametype`, `mode` (drops inode, device and capability noise).
* Redacted when matched: GitHub tokens, AWS access key ids, bearer/basic credentials,
  `password=`/`token=`/`secret=`/`api_key=` assignments, credentials in URLs, e-mail addresses
  (20 occurrences, all the placeholder `ci@example.invalid` passed to `git -c user.email=`),
  and public IPv4 addresses.
* Kept on purpose: the generic runner account names (`runner`, `root`) and the public repository
  URL used for the `git clone`.
* The collector refuses to write the corpus if any secret-shaped string survives, and
  `tests/test_benign.py` re-scans the committed file on every run.

## Result

| | |
|---|---|
| Events replayed | 675 (488 process-creation events) |
| Rules compiled | 26 |
| Rules with applicable benign events | 6 (5 Linux process/keyword rules and 1 Linux file-event rule) |
| Rules with no applicable benign events (not evaluated) | 20 (all Windows and AWS rules) |
| Rules that matched benign events | 1 |
| False-positive matches | 2 |

The one false positive is New Cron File Created (SigmaHQ `6c4e2f43`), 2 of 2 applicable file
events: `/etc/cron.daily/chkrootkit` and `/etc/cron.daily/chkrootkit.dpkg-new`, written by the
`chkrootkit` package install. That is the package-manager false positive the rule's own
`falsepositives` field warns about (its built-in filter only exempts `apt`, `dpkg`, `passwd`). It
was left in the workload on purpose.

## What this does not show

* One recording, 33 seconds, one runner image, one package set. Zero matches on the other five
  rules is not evidence that they are quiet on a real fleet; the history keyword rule is the most
  likely to differ, because it matches any event text.
* The Windows and AWS rules were not evaluated at all (there is no benign corpus for those planes),
  so the headline is a Linux-only false-positive figure.
* The workload deliberately avoids `chmod` with setuid/setgid and other technique-like behaviour,
  so it does not test the near-miss cases that unit tests cover.
* A real corpus should be recorded from the environment the rules will run in.
