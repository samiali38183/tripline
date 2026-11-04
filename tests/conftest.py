"""Shared fixtures: rule factory and repository paths."""

from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection

from tripline.engine.compiler import CompiledRule, compile_rule

REPO_ROOT = Path(__file__).resolve().parent.parent

RuleFactory = Callable[..., CompiledRule]


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


def _indent(block: str) -> str:
    return textwrap.indent(textwrap.dedent(block).strip("\n"), "    ")


@pytest.fixture
def make_rule() -> RuleFactory:
    """Compile a rule from a ``detection`` block (logsource defaults to windows/process_creation)."""

    def factory(
        detection: str, *, logsource: str = "product: windows\ncategory: process_creation"
    ) -> CompiledRule:
        yaml_text = "\n".join(
            [
                "title: test rule",
                "id: 11111111-2222-3333-4444-555555555555",
                "status: test",
                "logsource:",
                _indent(logsource),
                "detection:",
                _indent(detection),
                "",
            ]
        )
        collection = SigmaCollection.from_yaml(yaml_text)
        return compile_rule(collection.rules[0])

    return factory
