"""Load Sigma rules from disk and evaluate them against routed events."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

from tripline.engine.compiler import CompiledRule, UnsupportedRuleError, compile_rule
from tripline.logsource import LogSource, classify, normalize
from tripline.models import Event


@dataclass(frozen=True, slots=True)
class RuleLoadError:
    """A rule file that could not be parsed or compiled."""

    path: Path
    reason: str


@dataclass(slots=True)
class RuleSet:
    """Compiled rules plus the files that failed, so callers can fail loudly."""

    rules: list[CompiledRule]
    errors: list[RuleLoadError]

    def by_id(self, rule_id: str) -> CompiledRule | None:
        """Look up a compiled rule by its UUID string."""
        return next((r for r in self.rules if r.id == rule_id), None)

    def ids(self) -> set[str]:
        """All compiled rule ids."""
        return {r.id for r in self.rules}


def load_rules(directory: Path) -> RuleSet:
    """Recursively load ``*.yml``/``*.yaml`` Sigma rules under ``directory``."""
    rules: list[CompiledRule] = []
    errors: list[RuleLoadError] = []
    paths = sorted({*directory.rglob("*.yml"), *directory.rglob("*.yaml")})
    for path in paths:
        try:
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
            for sigma_rule in collection.rules:
                if not isinstance(sigma_rule, SigmaRule):
                    raise UnsupportedRuleError("correlation rules are not supported")
                rules.append(compile_rule(sigma_rule))
        except Exception as exc:  # every parse failure must be reported, not raised
            errors.append(RuleLoadError(path=path, reason=f"{type(exc).__name__}: {exc}"))
    seen: dict[str, CompiledRule] = {}
    for rule in rules:
        if rule.id in seen:
            errors.append(RuleLoadError(path=directory, reason=f"duplicate rule id {rule.id}"))
        seen[rule.id] = rule
    return RuleSet(rules=sorted(seen.values(), key=lambda r: r.id), errors=errors)


def rule_applies(rule: CompiledRule, sources: Iterable[LogSource]) -> bool:
    """True when the event's logsources satisfy the rule's ``logsource`` block."""
    return any(source.satisfies(rule.rule.logsource) for source in sources)


def evaluate(rule: CompiledRule, event: Event) -> bool | None:
    """Evaluate one rule on one raw event.

    Returns ``None`` when the rule's logsource does not apply to the event (the rule was not
    evaluated at all), otherwise the boolean match result on the normalised event.
    """
    sources = classify(event)
    if not rule_applies(rule, sources):
        return None
    return rule.matches(normalize(event))
