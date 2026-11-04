"""Load and validate ``scenarios/*.yaml``.

A scenario file is the unit of work for the whole pipeline: it names the technique, the
emulation that produces telemetry, the committed fixtures and the Sigma rules that must fire.
Validation is strict (unknown keys are rejected) so a typo in ``expected_rules`` fails the
loader rather than silently passing the gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from tripline.models import Scenario


@dataclass(frozen=True, slots=True)
class ScenarioLoadError(ValueError):
    """A scenario file failed to parse or validate."""

    path: Path
    reason: str

    def __str__(self) -> str:
        """Render as ``path: reason``."""
        return f"{self.path}: {self.reason}"


def load_scenario(path: Path) -> Scenario:
    """Load and validate one scenario file."""
    try:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ScenarioLoadError(path, f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ScenarioLoadError(path, "top level must be a mapping")
    try:
        return Scenario.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(loc) for loc in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors()
        )
        raise ScenarioLoadError(path, problems) from exc


def load_scenarios(directory: Path) -> list[Scenario]:
    """Load every ``*.yaml`` scenario in ``directory``, sorted by id, rejecting duplicate ids."""
    paths = sorted(directory.glob("*.yaml"))
    if not paths:
        raise ScenarioLoadError(directory, "no *.yaml scenario files found")
    scenarios = [load_scenario(p) for p in paths]
    seen: dict[str, Path] = {}
    for scenario, path in zip(scenarios, paths, strict=True):
        if scenario.id in seen:
            raise ScenarioLoadError(path, f"duplicate scenario id {scenario.id!r}")
        seen[scenario.id] = path
    return sorted(scenarios, key=lambda s: s.id)


def validate_fixture_paths(scenarios: list[Scenario], root: Path) -> list[str]:
    """Return a problem per fixture path that does not exist under ``root``."""
    return [
        f"{scenario.id}: fixture {fixture.path} not found"
        for scenario in scenarios
        for fixture in scenario.fixtures
        if not (root / fixture.path).is_file()
    ]
