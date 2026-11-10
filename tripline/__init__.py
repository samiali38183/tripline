"""tripline: a detection quality gate.

Replays recorded ATT&CK emulation telemetry (NDJSON fixtures) through Sigma rules with a
pure-Python evaluator and scores prevalence-weighted coverage, so a CI job can fail a pull
request when an expected rule stops firing. Precision, robustness and cost scoring are on the
roadmap, not implemented.
"""

__version__ = "0.2.0"
