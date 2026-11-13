# Where the prevalence weights come from

Each scenario carries a weight from 1 to 10. Coverage is `sum(weight x coverage) / sum(weight)`.

## What was checked

The Red Canary Threat Detection Report site publishes a top-10 technique chart for the 2026
report ("observed in confirmed threats across the Red Canary customer base in 2025"):
<https://redcanary.com/threat-detection-report/techniques/> (read 2026-11-11; the page shows ranks
without percentages). The ranking is:

1. T1078.004 Cloud Accounts
2. T1059.001 PowerShell
3. T1059.003 Windows Command Shell
4. T1530 Data from Cloud Storage
5. T1105 Ingress Tool Transfer
6. T1114.003 Email Forwarding Rule
7. T1047 Windows Management Instrumentation
8. T1204.004 Malicious Copy and Paste
9. T1564.008 Email Hiding Rules
10. T1027 Obfuscated Files or Information

## Mapping

For the techniques in that top 10 that have a scenario, the weight equals `11 - rank`
(T1078.004 = 10, T1059.001 = 9, T1059.003 = 8, T1530 = 7, T1105 = 6, T1047 = 4, T1027 = 1). The
committed weights match this rule for all seven. That is 45 of the 62 weight points.
T1114.003, T1204.004 and T1564.008 are top-10 techniques with no scenario; they are listed as
known gaps in the Navigator layer.

The other seven scenarios (T1003.001 = 3, T1685.002 = 3, T1098.001 = 3, T1053.003 = 2,
T1053.005 = 2, T1070.003 = 2, T1548.001 = 2) are not in the published top 10. Their weights are
hand-assigned low values, not taken from any ranking (17 of 62 points).

## Caveats

* The ranking is Red Canary's customer detections, mostly endpoint and identity telemetry; it
  is a proxy for prevalence, not a measurement of any other environment.
* Only the top 10 is published on the page that was read. Ranks below 10 were not retrieved.
* The page was read once; if Red Canary revises the chart the weights should be re-derived.
