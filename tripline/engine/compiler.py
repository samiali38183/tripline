"""Compile Sigma rules into Python predicates.

pySigma parses the YAML, applies value modifiers (``contains``, ``windash``, ``re``...)
and builds the condition tree; this module walks that tree and turns every leaf into a
closure over an event. No SIEM is involved, so the same rule can be evaluated in CI against
committed NDJSON fixtures.

Anything the engine cannot evaluate faithfully (placeholders, backend query expressions,
aggregations, ``near``) raises :class:`UnsupportedRuleError` instead of silently passing:
a rule the gate cannot evaluate must fail the gate, not slip through it.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from tripline.events import get_field, has_field, iter_leaf_values
from tripline.models import Event

Predicate = Callable[[Event], bool]

_COMPARE: dict[str, Callable[[float, float], bool]] = {
    "LT": lambda a, b: a < b,
    "LTE": lambda a, b: a <= b,
    "GT": lambda a, b: a > b,
    "GTE": lambda a, b: a >= b,
    "NEQ": lambda a, b: a != b,
}


class UnsupportedRuleError(ValueError):
    """Raised when a rule uses a Sigma feature the pure-Python engine does not implement."""


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A Sigma rule paired with its executable predicate."""

    rule: SigmaRule
    predicate: Predicate
    techniques: tuple[str, ...] = field(default_factory=tuple)

    @property
    def id(self) -> str:
        """Sigma rule id (string form of the UUID)."""
        return str(self.rule.id)

    @property
    def title(self) -> str:
        """Rule title."""
        return str(self.rule.title)

    def matches(self, event: Event) -> bool:
        """Evaluate the rule's detection logic against one event."""
        return self.predicate(event)


def compile_rule(rule: SigmaRule) -> CompiledRule:
    """Compile a parsed :class:`SigmaRule` into a :class:`CompiledRule`."""
    if rule.id is None:
        raise UnsupportedRuleError(f"rule {rule.title!r} has no id; every rule needs a UUID")
    conditions = rule.detection.parsed_condition
    if not conditions:
        raise UnsupportedRuleError(f"{rule.title}: rule has no condition")
    predicates = [_compile_node(c.parsed, rule) for c in conditions]
    predicate = predicates[0] if len(predicates) == 1 else _any_of(predicates)
    techniques = tuple(
        tag.name.upper()
        for tag in rule.tags
        if tag.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", tag.name)
    )
    return CompiledRule(rule=rule, predicate=predicate, techniques=techniques)


def _any_of(predicates: list[Predicate]) -> Predicate:
    return lambda event: any(p(event) for p in predicates)


def _compile_node(node: ConditionItem | Any, rule: SigmaRule) -> Predicate:
    if isinstance(node, ConditionAND):
        parts = [_compile_node(arg, rule) for arg in node.args]
        return lambda event: all(p(event) for p in parts)
    if isinstance(node, ConditionOR):
        parts = [_compile_node(arg, rule) for arg in node.args]
        return lambda event: any(p(event) for p in parts)
    if isinstance(node, ConditionNOT):
        inner = _compile_node(node.args[0], rule)
        return lambda event: not inner(event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _compile_field_test(str(node.field), node.value, rule)
    if isinstance(node, ConditionValueExpression):
        return _compile_keyword(node.value, rule)
    raise UnsupportedRuleError(f"{rule.title}: unsupported condition node {type(node).__name__}")


def _compile_field_test(field_name: str, value: Any, rule: SigmaRule) -> Predicate:
    if isinstance(value, SigmaExpansion):
        alternatives = [_compile_field_test(field_name, v, rule) for v in value.values]
        return lambda event: any(p(event) for p in alternatives)
    if isinstance(value, SigmaNull):
        return lambda event: get_field(event, field_name) is None
    if isinstance(value, SigmaExists):
        expected = bool(value.exists)
        return lambda event: has_field(event, field_name) is expected
    if isinstance(value, SigmaFieldReference):
        other = str(value.field)
        return lambda event: _field_ref_matches(event, field_name, other, value)
    matcher = _value_matcher(value, rule)
    return lambda event: _any_scalar(get_field(event, field_name), matcher)


def _compile_keyword(value: Any, rule: SigmaRule) -> Predicate:
    """Field-less keyword: true if any scalar in the event *contains* the keyword."""
    if isinstance(value, SigmaString):
        pattern = _string_to_regex(value, anchored=False)
        return lambda event: any(
            pattern.search(_to_text(leaf)) is not None for leaf in iter_leaf_values(event)
        )
    if isinstance(value, SigmaRegularExpression):
        regex = _compile_regex(value)
        return lambda event: any(
            regex.search(_to_text(leaf)) is not None for leaf in iter_leaf_values(event)
        )
    raise UnsupportedRuleError(
        f"{rule.title}: keyword of type {type(value).__name__} is not supported"
    )


def _value_matcher(value: Any, rule: SigmaRule) -> Callable[[Any], bool]:
    if isinstance(value, SigmaString):
        pattern = _string_to_regex(value, anchored=True)
        return lambda actual: pattern.fullmatch(_to_text(actual)) is not None
    if isinstance(value, SigmaRegularExpression):
        regex = _compile_regex(value)
        return lambda actual: regex.search(_to_text(actual)) is not None
    if isinstance(value, SigmaNumber):
        expected = value.number
        return lambda actual: _numeric_equal(actual, expected)
    if isinstance(value, SigmaBool):
        expected_bool = bool(value.boolean)
        return lambda actual: isinstance(actual, bool) and actual is expected_bool
    if isinstance(value, SigmaCIDRExpression):
        network = ipaddress.ip_network(str(value.cidr), strict=False)
        return lambda actual: _in_network(actual, network)
    if isinstance(value, SigmaCompareExpression):
        op = _COMPARE[value.op.name]
        threshold = float(value.number.number)
        return lambda actual: _compare(actual, threshold, op)
    raise UnsupportedRuleError(
        f"{rule.title}: value type {type(value).__name__} is not supported by the engine"
    )


def _compile_regex(value: SigmaRegularExpression) -> re.Pattern[str]:
    """Compile a Sigma ``|re`` value honouring its ``i``/``m``/``s`` flags.

    Unlike plain Sigma strings, regular expressions are case-sensitive unless the rule asks
    for ``|re|i``; that matches both the specification and the OpenSearch backend.
    """
    flags = 0
    for flag in value.flags:
        flags |= value.sigma_to_python_flags[flag]
    return re.compile(str(value.regexp), flags)


def _string_to_regex(value: SigmaString, *, anchored: bool) -> re.Pattern[str]:
    """Translate a Sigma string (with ``*``/``?`` wildcards) into a compiled regex.

    Sigma string comparison is case-insensitive unless the ``cased`` modifier was used.
    """
    chunks: list[str] = []
    for part in value.s:
        if isinstance(part, str):
            chunks.append(re.escape(part))
        elif part is SpecialChars.WILDCARD_MULTI:
            chunks.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            chunks.append(".")
        else:
            raise UnsupportedRuleError(
                f"placeholder {part!r} must be expanded by a pipeline before evaluation"
            )
    flags = re.DOTALL
    if not isinstance(value, SigmaCasedString):
        flags |= re.IGNORECASE
    body = "".join(chunks)
    return re.compile(body if anchored else f"(?:{body})", flags)


def _any_scalar(actual: Any, matcher: Callable[[Any], bool]) -> bool:
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(_any_scalar(item, matcher) for item in actual)
    return matcher(actual)


def _to_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _numeric_equal(actual: Any, expected: int | float) -> bool:
    if isinstance(actual, bool):
        return False
    if isinstance(actual, int | float):
        return actual == expected
    try:
        return float(str(actual)) == float(expected)
    except ValueError:
        return False


def _compare(actual: Any, threshold: float, op: Callable[[float, float], bool]) -> bool:
    if isinstance(actual, bool):
        return False
    try:
        return op(float(actual), threshold)
    except (TypeError, ValueError):
        return False


def _in_network(actual: Any, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        return ipaddress.ip_address(str(actual)) in network
    except ValueError:
        return False


def _field_ref_matches(event: Event, field_name: str, other: str, ref: SigmaFieldReference) -> bool:
    """Compare two fields of the same event (``|fieldref`` and its ``contains`` etc. variants).

    pySigma encodes ``fieldref|contains`` as ``starts_with and ends_with`` both set, so that
    case is tested first. Comparison is case-insensitive like plain Sigma strings.
    """
    left, right = get_field(event, field_name), get_field(event, other)
    if left is None or right is None:
        return False
    left_text, right_text = _to_text(left).lower(), _to_text(right).lower()
    if ref.starts_with and ref.ends_with:
        return right_text in left_text
    if ref.starts_with:
        return left_text.startswith(right_text)
    if ref.ends_with:
        return left_text.endswith(right_text)
    return left_text == right_text
