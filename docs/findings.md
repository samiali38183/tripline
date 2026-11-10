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
  `chmod a+s` is equally invisible to the rule. Result on the recorded fixture: 0 of 36 applicable
  events.
* **Fix:** `rules/sigma/linux/tripline_lnx_chmod_setuid_setgid_any_form.yml`
  (`7f3c2b1a-6d4e-4a9b-9c8d-1e2f3a4b5c6d`) matches `Image|endswith: /chmod` with a regex over the
  symbolic form `[ugoa]*[+=][rwxXt]*s` or a 4-digit octal mode starting with 2/4/6. On the same
  fixture: 2 of 36 applicable events (the two `chmod` executions), the wrapper `sh -c` line is not
  double-counted because the `Image` must be `chmod` itself.
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
* **Open observation:** for the same processes, Sysmon EID 1 `CommandLine` shows `%%TEMP%%` and
  `%%LOCALAPPDATA:~-3,1%%` while Security 4688 shows `%TEMP%`. Not explained yet; any rule that
  matches a literal `%VAR%` will behave differently per source.
