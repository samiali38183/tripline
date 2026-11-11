# Contributing

## Setup

```bash
git clone https://github.com/samiali38183/tripline && cd tripline
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
tripline validate && tripline replay --all
```

## Quality gates (all run in CI)

```bash
ruff format tripline tests && ruff check tripline tests
mypy tripline                     # strict
pytest --cov=tripline
sigma check rules/
tripline replay --all             # the detection gate; exit 1 = an expected rule missed
```

## Adding a scenario

1. Create `scenarios/<technique>-<slug>.yaml` (strict schema: unknown keys are rejected, see
   `tripline/models.py::Scenario`). Weight is 11 minus the technique's rank in the Red Canary
   Threat Detection Report top 10 when it is listed there; otherwise a low hand-assigned value
   (see `docs/weights.md`; do not present a hand-assigned weight as sourced).
2. Add or vendor the Sigma rule(s) under `rules/sigma/<plane>/`. SigmaHQ rules are copied verbatim
   with the two-line attribution header (`rules/sigma/LICENSE-DRL.md`).
3. Cloud scenarios: add a `Recipe` to `tripline/cloud/sources.py` and run `tripline cloud build`.
   Commit `run.ndjson` **and** `manifest.json`, and extend `fixtures/cloud/SOURCES.md`.
4. Endpoint scenarios: list the Atomic Red Team test GUIDs; leave `fixtures: []` until a recorded
   fixture exists. Pending scenarios are reported, never gate.
5. `tripline validate` must pass and `tests/test_scenarios.py` must be updated if the scenario
   count or technique set changes (the design table is asserted).

## Changing the engine

The compiler walks pySigma's parsed condition tree (`tripline/engine/compiler.py`). Add a test in
`tests/test_compiler.py` for every modifier or condition form you touch, including a negative case.
Features the engine cannot evaluate must raise `UnsupportedRuleError` rather than silently
returning `False`.

## Commits and PRs

Small, single-purpose commits; CI must be green. A PR that makes `tripline replay --all` fail is a
detection regression and will be blocked by the gate - that is the point.
