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
