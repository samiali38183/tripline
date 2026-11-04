"""tripline: a detection quality gate.

Replays ATT&CK telemetry (recorded or synthetic NDJSON fixtures) through Sigma rules
with a pure-Python engine and scores every rule on coverage, precision, robustness
and cost so a CI job can fail a pull request on detection regressions.
"""

__version__ = "0.1.0"
