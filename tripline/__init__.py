"""tripline: a detection quality gate.

Replays recorded ATT&CK emulation telemetry (NDJSON fixtures) through Sigma rules with a
pure-Python evaluator and scores prevalence-weighted coverage, so a CI job can fail a pull
request when an expected rule stops firing. It also replays every rule over a benign corpus
(false positives) and sweeps command-line variants of the Linux attacks (evasion). It is not a
replacement for SigmaHQ regression data, rsigma or SCYTHE; see docs/related-work.md.
"""

__version__ = "0.3.0"
