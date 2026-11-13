# Cloud fixture provenance

Every file under `fixtures/cloud/<scenario>/run.ndjson` is real AWS CloudTrail telemetry from
a public dataset, passed through `tripline cloud build` (`tripline/cloud/sources.py`), which:

1. selects records with the predicate shown in the recipe (reviewable Python, not hand edits);
2. rebases every `eventTime` so the oldest record lands at build time with original offsets kept;
3. appends `tripline/<run-guid>` to `userAgent` so a SIEM can attribute the replay to one run.

`manifest.json` next to each fixture records the run GUID, event count, event names, the original
and replayed time windows and the upstream sources. Payload fields are otherwise untouched -
account ids, ARNs and IPs are whatever the publishers released.

| Scenario | Events | Source | Licence |
|---|---|---|---|
| t1078-004-console-login-without-mfa | 7 | Stratus Red Team detonation log `aws.initial-access.console-login-without-mfa.json` (1 IAM-user login, MFAUsed=No) + 6 root `ConsoleLogin` records from flaws.cloud | Apache-2.0 / public dataset |
| t1530-s3-bucket-exposure | 10 | flaws.cloud: `PutBucketAcl`/`PutBucketPolicy` granting AllUsers or Principal `*`, and `ListBuckets` by the leaked `backup` IAM user | public dataset |
| t1562-008-cloudtrail-stop | 1 | Stratus Red Team detonation log `aws.defense-evasion.cloudtrail-stop.json` | Apache-2.0 |
| t1098-001-iam-backdoor-access-key | 1 | Stratus Red Team detonation log `aws.persistence.iam-backdoor-user.json` | Apache-2.0 |

## Sources

* Stratus Red Team detonation logs - DataDog, <https://github.com/DataDog/stratus-red-team/tree/main/docs/detonation-logs>,
  captured with Grimoire. Licence: Apache-2.0 (<https://github.com/DataDog/stratus-red-team/blob/main/LICENSE>).
* flaws.cloud CloudTrail dataset - Scott Piper / Summit Route,
  <https://summitroute.com/downloads/flaws_cloudtrail_logs.tar> (2017-2020), published for
  public analysis: <https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/>.

Rebuild from upstream with `tripline cloud build` (downloads about 250 MB into `.cache/`); the run GUID
and timestamps will differ, the selected records will not unless upstream changes.
