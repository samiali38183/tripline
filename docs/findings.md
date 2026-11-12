# Findings

Detection gaps surfaced by replaying real emulation telemetry. Each entry names the telemetry,
the rule that should have fired, why it did not, and what changed.

## F-001 - SigmaHQ "Setuid and Setgid" misses `chmod u+xs`

* **Scenario:** `t1548-001-setuid-setgid` (T1548.001, Linux)
* **Telemetry:** auditd EXECVE from `ubuntu-latest`, Atomic Red Team T1548.001-3 and -5,
  recorded in [emulate-linux run 41838714456](https://github.com/samiali38183/tripline/actions/runs/41838714456)
  and committed under `fixtures/linux/t1548-001-setuid-setgid/`.
* **Observed command lines:**

  ```
  sh -c sudo touch /tmp/evilBinary; sudo chown root /tmp/evilBinary; sudo chmod u+xs /tmp/evilBinary
  chmod u+xs /tmp/evilBinary
  chmod g+xs /tmp/evilBinary
  ```

* **Rule:** `c21c4eaa-ba2e-419a-92b2-8371703cbe21` *Setuid and Setgid* (SigmaHQ, vendored unmodified)
  requires `CommandLine|contains: ' chmod u+s'` or `' chmod g+s'` **and** `'chown root'`.
* **Why it missed:** the atomic uses the combined mode `u+xs` / `g+xs`. A `contains` match on the
  literal ` chmod u+s` cannot see it. Any attacker typing `chmod 4755`, `chmod ug+s` or
  `chmod a+s` is equally invisible to the rule. Result on the recorded fixture: 0 of the 2 attack events.
  All 36 recorded events apply to the rule: 2 are the attack (the two `chmod` executions), 4 are
  `sudo`/`dash` wrapper lines that mention `chmod`, 30 are unrelated.
* **Fix:** `rules/sigma/linux/tripline_lnx_chmod_setuid_setgid_any_form.yml`
  (`7f3c2b1a-6d4e-4a9b-9c8d-1e2f3a4b5c6d`) matches `Image|endswith: /chmod` with a regex over the
  symbolic form `[ugoa]*[+=][rwxXt]*s` or an octal mode. On the same fixture: 2 of 2 attack events
  (the two `chmod` executions; the replay prints this as 2/36 applicable events, 36 being all
  recorded events). The wrapper lines are not counted because the
  `Image` must be `chmod` itself.
* **Revision in 0.2.1 (review findings).** The first version of the rule had its own gaps, found
  by reading the regexes against hand-built command lines (synthetic events in
  `tests/test_linux_collect.py`, not recorded telemetry; the committed fixtures and the 2 of 2
  result are unchanged):
  * The octal branch matched only `[2467][0-7]{3}`. The special-bits digit is a bitmask (4 setuid,
    2 setgid, 1 sticky), so `3755` (setgid+sticky) and `5755` (setuid+sticky) were missed, and a
    leading zero (`04755`, `02755`) was missed because exactly four digits had to follow. It is
    now `0?[2-7][0-7]{3}`; sticky-only (`1755`, `01755`) still does not match.
  * The symbolic branch only looked at the first clause of the mode, so `g+w,u+s` and
    `a+rx,g+xs` were missed. It now walks a comma-separated clause list. `u-s` (clearing the bit)
    still does not match.
  * Both branches required whitespace before `chmod`, so an invocation by full path
    (`/usr/bin/chmod 4755 ...`) was missed; a `/` is now accepted. Option words such as `--` are
    accepted as well as `-R`.
  * The filter `CommandLine|contains: '/usr/share/doc/'` suppressed any setuid chmod whose command
    line contained that string anywhere, so appending `/usr/share/doc/` as an extra argument (or
    using `/tmp/usr/share/doc/x`) evaded the rule. The filter is now a regex that excludes an
    event only when *every* file operand is under `/usr/share/doc/` and no operand contains
    `..`. Residual risk: a symlink inside `/usr/share/doc` that points elsewhere is still
    excluded; the rule sees the command line, not the resolved path.
* **Status:** scenario now expects the tripline rule; the SigmaHQ rule stays in the rule set so a
  future upstream fix is picked up by `tripline replay` automatically. Upstream issue: to be filed.

## F-002 - auditd SYSCALL registers leak into command lines (collector bug)

* **Where:** `tripline/linux/collect.py`, first runner recording.
* **Symptom:** merged EXECVE events ended with garbage (`touch /tmp/evilBinary V\u0010\u001a…`).
* **Cause:** a SYSCALL record carries `a0..a3` as raw register values (pointers); the collector
  hex-decoded them like EXECVE arguments and they survived the merge as an extra `a3`.
* **Fix:** SYSCALL `a0..a3` are dropped; hex decoding only applies to EXECVE arguments and
  PROCTITLE. Regression test: `tests/test_linux_collect.py::test_parse_merges_records_and_decodes_hex`.

## F-003 - First scheduled Windows run: 1 of 7 pass, and why the other 6 failed

* **Run:** [emulate-windows run 42658659666](https://github.com/samiali38183/tripline/actions/runs/42658659666)
  (scheduled, `windows-latest`, build 10.0.26100 = Windows Server 2025). Reproduced offline from
  the run artifact with `tripline windows collect events.ndjson --run-guid ... --replay`; same
  verdicts. No Windows fixtures are committed from this run.
* **Passed:** T1105 (certutil 1/9, bitsadmin 1/9 applicable events).
* **Runner problems, fixed in `emulate-windows.yml`:**
  * T1003.001: `Potential Credential Dumping Activity Via LSASS` showed `0/0 applicable events`.
    The SwiftOnSecurity Sysmon config has an empty `ProcessAccess` include block, so Sysmon EID 10
    is never logged. The dump itself happened (Sysmon EID 11 for `lsass-comsvcs.dmp`, and the
    comsvcs rule fired 2/6). The workflow now adds a `TargetImage end with \lsass.exe` include.
  * T1047: `'wmic' is not recognized`. WMIC is an optional feature on Server 2025 and is not
    installed on the image. The workflow now adds the `WMIC` capability before the atomics.
  * T1059.001 test 16: prereq `Install-Module AtomicTestHarnesses` failed with "PowerShellGet
    could not be loaded" inside the Windows PowerShell 5.1 child that Invoke-AtomicTest starts
    from pwsh 7 (most likely because the child inherits pwsh's `PSModulePath`), so
    `Out-ATHPowerShellCommandLineParameter` never existed. The module is now installed from a
    Windows PowerShell step and the atomics run under `shell: powershell`.
* **Scenario problems, not fixed yet (need a decision, not a workflow change):**
  * T1059.001 test `cc50fa2a` (*Powershell Invoke-DownloadCradle*) is a `manual` executor in
    Atomic Red Team, so Invoke-AtomicTest reports "Found 0 atomic tests" and runs nothing. The
    download-cradle half of the scenario has no automated emulation. Needs a different atomic.
  * T1059.001: `Suspicious Execution of Powershell with Base64` matched 1/5, but on the wrapper
    text `-EncodedCommandParamVariation` (contains ` -enco`), not on a real `-EncodedCommand`.
    That pass is a coincidence and should not be trusted once the prereq works.
  * T1027: `Obfuscated PowerShell OneLiner Execution` (`44e24481`) requires the literal strings
    `http://127.0.0.1`, `%{(IRM $_)}` and `Invoke`. It is written for one specific cradle; neither
    T1027-7 (format-string obfuscation) nor T1027-11 (char array) can match it. 0/10.
  * T1053.005: `Suspicious Scheduled Task Creation` (`3a734d25`) requires the 4698 `TaskContent`
    to reference a user-writable path (`\AppData\`, `\Users\Public\`, ...) and a LOLBin. The atomic
    registers `C:\windows\system32\cmd.exe`, so only the second half matches. 0/6. The 4698 event
    itself was captured, so the audit policy works.
  * T1059.003: `Potentially Suspicious CMD Shell Output Redirect` (`8e0bb260`) needs the
    redirect target to be written out (`> %TEMP%\...` or `C:\Users\...\AppData\Local\`). Both
    atomics redirect to a relative file name (`> hello.txt`, `> AtomicTest.vbs`) after the
    working directory is already `%TEMP%`. The file still lands in a suspicious folder, but the
    command line does not say so. 0/13. This is a real evasion of the rule, same family as F-001.
* **Update, run [43090565998](https://github.com/samiali38183/tripline/actions/runs/43090565998)
  (0.3.0, `windows-latest`):** recorded telemetry confirms the two tripline rules below and the
  encoded-command half of T1059.001, so three scenarios now pass with committed fixtures.
  * T1059.003: SigmaHQ `8e0bb260` matched 0 of 11 applicable events; tripline
    `467585b7` matched 2 of 11 (Sysmon EID 1, `echo ... > hello.txt` and `> AtomicTest.vbs` from a
    Temp working directory). The scenario now expects the tripline rule.
  * T1053.005: SigmaHQ `3a734d25` matched 0 of 6 applicable events; tripline `eb3f5405` matched 1
    of 6 (the 4698 event for `schtasks /Create ... /TR C:\windows\system32\cmd.exe`). The
    scenario expects the tripline rule next to SigmaHQ `92626ddd` (1 of 4).
  * T1059.001: ART #17 (`powershell.exe -e <base64>`, replacing the manual-only #9) and #15 ran;
    SigmaHQ `fb843269` matched 3 of 22 Sysmon/Security process events, including the real
    `powershell.exe  -e  JgAg...` command line. The download-cradle rule `403c2cc0` matched 0 of 75
    script blocks: no automated atomic runs a `System.Net.WebClient` cradle, so that half was
    removed from the scenario rather than claimed.
  * T1027: still pending. The recording (ART #7, #11 and #2) gave `44e24481` 0 of 15 applicable
    events. `fb843269` fires on the base64 atomic (#2), but that is the T1059.001 rule, and
    re-labelling T1027 to expect it would raise the number without testing an obfuscation rule.
  * The tripline rules were written in 0.2.1 from the F-003 analysis and were not edited after
    this recording; a caveat remains that two of them are tuned to the Atomic tests' command shape.
  Attempts used: 1 (of 2 allowed).
* **Added in 0.2.1 (original note, superseded by the update above).** Two tripline rules target the
  T1059.003 and T1053.005 gaps above. They are exercised only by hand-written synthetic events in
  `tests/test_windows_rules.py` (labelled synthetic there; nothing under `fixtures/`, nothing
  counted in the scorecard). No scenario expects them yet and all seven Windows scenarios stay
  pending. After the next recorded Windows run, replace the SigmaHQ rule in the scenario's
  `expected_rules` only if the tripline rule fires on the real events.
  * `tripline_win_cmd_redirect_relative_in_suspicious_cwd.yml` (`467585b7-9de8-40e5-bb2a-6626902ae295`):
    cmd.exe with a `>` or `>>` to a relative file name while Sysmon's `CurrentDirectory` is a Temp,
    AppData, `Users\Public`, `ProgramData` or `C:\Temp` folder. Sysmon EID 1 only (Security 4688
    has no working directory). Depends on the atomics really running with that working directory,
    which F-003 inferred from where the files landed and has not been read from a recorded
    `CurrentDirectory`. Known false positive: `>nul` from a temp directory.
  * `tripline_win_security_scheduled_task_interpreter_action.yml` (`eb3f5405-928e-441c-a867-0612f0f66dc9`):
    a 4698 task whose `<Command>` is cmd, powershell, pwsh, wscript, cscript, mshta, rundll32,
    regsvr32, certutil, bitsadmin or wmic, wherever the binary lives; tasks named under
    `\Microsoft\` are excluded (spoofable by an attacker who names a task the same way).
* **Not done in 0.2.1 (needs Windows runs or a scenario decision):** the manual-only `cc50fa2a`
  atomic, the T1027 rule (a replacement would be guesswork without the recorded command lines of
  T1027-7 and T1027-11), and the T1059.001 pass that comes from the wrapper parameter text.
* **Open observation:** for the same processes, Sysmon EID 1 `CommandLine` shows `%%TEMP%%` and
  `%%LOCALAPPDATA:~-3,1%%` while Security 4688 shows `%TEMP%`. Not explained yet; any rule that
  matches a literal `%VAR%` will behave differently per source.

## F-004 - Evasion sweep: what the first variant run showed (0.3.0)

* **Method:** `tripline robustness` (seed 20261111; [`robustness.md`](robustness.md)) generates
  deterministic command-line variants of the three Linux attacks and replays them. 251
  command-line variants and 4 alternative-tool variants in total.
* **Setuid rule family (108 command-line variants):** the tripline replacement caught 105 before
  and 106 after this change; the vendored SigmaHQ *Setuid and Setgid* rule caught 0 of 108 (it
  requires `chown root` in the same command line and a literal ` chmod u+s`).
  * **Fixed:** `busybox chmod u+s f` runs as `/usr/bin/busybox`, so the `Image` selection missed
    it. The selection now accepts `/busybox`; the command-line patterns still need the `chmod`
    token. Tests: `test_setuid_rule_catches_busybox_multicall_form` (also a benign busybox form and
    another applet).
  * **Documented, not fixed:** `chmod u+s` on a file under `/usr/share/doc/` is exempted by the
    package-documentation filter (a deliberate false-positive trade-off); a renamed copy of
    `chmod` (`Image` and argv no longer say chmod) cannot be matched on the command line; the four
    alternative-tool variants (`install -m 4755`, `python3 os.chmod`, `perl chmod`) are outside the
    rule's scope (0 of 4).
* **History clearing (103 variants):** an expected rule catches 71. All `rm`, binary-path and flag
  variants are caught; misses are concentrated in shell builtins and wrapper text. The vendored
  keyword rule matches literal strings, so `history  -c` (two spaces), a tab, `"history" -c`,
  `h''istory -c`, `HISTFILESIZE=0` without `export`, `export HISTSIZE=0`, `HISTFILE=/dev/null`,
  `set +o history`, `> ~/.bash_history`, `: > file`, `truncate -s 0`, `truncate --size=0`,
  `ln -s -f`, `cp /dev/null` and `dd if=/dev/null` are not caught. `unset HISTFILE` is excluded
  upstream on purpose (false-positive prone). These are gaps in vendored rules, reported not patched.
* **Cron (40 variants):** an expected rule catches 23. The crontab rule only fires when the
  argument contains `/tmp/` (`crontab /dev/shm/x`, `./x`, `~/x`, `-` from stdin are missed); the
  file rule's allow-list exempts `/etc/cron.daily/apt` and `/etc/cron.daily/dpkg` (an attacker
  can use those names), it misses `/etc/./cron.d/x`, `/var/spool/cron/<user>` and `/etc/anacrontab`.
* **Limits:** the lists are hand-written, not exhaustive; a catch rate over them does not
  measure real-world evasion.
