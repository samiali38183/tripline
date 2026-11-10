# Gate proof

The detection gate is only worth something if it goes red when a rule regresses. This page records
the pull request that proved it.

## PR #1 - deliberately break one cloud rule

* PR: <https://github.com/samiali38183/tripline/pull/1> (closed unmerged, branch deleted)
* CI run: <https://github.com/samiali38183/tripline/actions/runs/41833670332> - **failure**
  * `detection gate (tripline replay --all)`: <https://github.com/samiali38183/tripline/actions/runs/41833670332/job/126586961570> - fail
  * `lint, types, tests`: <https://github.com/samiali38183/tripline/actions/runs/41833670332/job/126586961141> - fail
    (the committed-fixture tests in `tests/test_replay.py` and `tests/test_cli.py` also catch it)

### The change

One line in `rules/sigma/cloud/tripline_aws_console_login_without_mfa.yml`:

```diff
-        additionalEventData.MFAUsed: 'No'
+        additionalEventData.MFAUsed: 'Maybe'
```

The rule still compiles and `sigma check` still passes - this is exactly the class of regression a
linter cannot see and only replaying real telemetry catches.

### What CI said

Gate job log:

```
[   FAIL] t1078-004-console-login-without-mfa (T1078.004, aws) - 7 events
     - 3b1f0d2e-7c4a-4d5b-9e8f-2a6c1d0b9f41  AWS Console Login Without MFA  (0/7 applicable events (rule did not match))
     + 8ad1600d-e9dc-4251-b0ee-a65268f29add  AWS Root Credentials  (6/7 applicable events)
GATE FAILED: 1 scenario(s) missed an expected rule: t1078-004-console-login-without-mfa
```

PR comment posted by `actions/github-script` (excerpt):

```
### tripline detection gate: FAILED

**Gate:** FAILED - 3 passed, 1 failed, 10 pending of 14 scenarios; 22 expected rules.
**Prevalence-weighted coverage:** 21% of all scenarios, 57% of scenarios with fixtures.

| t1078-004-console-login-without-mfa | T1078.004 | aws | 10 | FAIL (3b1f0d2e-7c4a-4d5b-9e8f-2a6c1d0b9f41) | 1/2 | 7 |
```

Weighted coverage dropped from 37 % to 21 % because T1078.004 carries the highest prevalence weight
(10) in the scenario set - the scorecard shows the *business* impact of the regression, not just a
red X.

### Reproduce locally

```bash
sed -i "s/MFAUsed: 'No'/MFAUsed: 'Maybe'/" rules/sigma/cloud/tripline_aws_console_login_without_mfa.yml
tripline replay --all      # exit 1, names the scenario
git checkout rules/
```

`tests/test_cli.py::test_replay_gate_fails_and_names_scenario` performs the same edit on a
temporary copy of the repository, so the proof is also part of the unit suite.
