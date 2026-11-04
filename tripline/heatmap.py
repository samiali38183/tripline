"""Render a scorecard as an ATT&CK Navigator layer (format 4.5).

Each technique that has a scenario gets a cell whose score is its prevalence-weighted
coverage on a 0-100 scale, coloured on a red-to-green gradient. Techniques listed in
``KNOWN_GAPS`` are deliberately not emulated (no M365/Gmail tenant, user-driven technique);
they are rendered grey with a comment so the heatmap states risk explicitly instead of
leaving blank cells that look like "not applicable".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tripline.models import Scorecard, TechniqueCoverage

LAYER_VERSION = "4.5"
ATTACK_VERSION = "16"
NAVIGATOR_VERSION = "5.1.0"

GAP_COLOR = "#9e9e9e"
PENDING_COLOR = "#e0e0e0"
GRADIENT = ["#d32f2f", "#fbc02d", "#388e3c"]

KNOWN_GAPS: dict[str, str] = {
    "T1114.003": "Email Forwarding Rule - needs an M365/Google Workspace tenant; not emulated.",
    "T1564.008": "Email Hiding Rules - needs an M365/Google Workspace tenant; not emulated.",
    "T1204.004": "Malicious Copy and Paste (ClickFix) - user-driven; candidate for a later phase.",
}
"""Techniques the project knowingly does not cover. Shown grey on the heatmap."""


def build_layer(scorecard: Scorecard, *, name: str = "tripline coverage") -> dict[str, Any]:
    """Build a Navigator v4.5 layer dictionary from a scorecard."""
    techniques = [_technique_cell(t) for t in scorecard.techniques]
    techniques.extend(_gap_cell(technique, why) for technique, why in sorted(KNOWN_GAPS.items()))
    totals = scorecard.totals
    description = (
        f"Prevalence-weighted Sigma coverage from tripline scorecard "
        f"({totals.passed}/{totals.scenarios} scenarios passed, {totals.pending} pending). "
        f"Weighted coverage {totals.weighted_coverage:.0%} overall"
        + (
            f", {totals.weighted_coverage_scored:.0%} over scenarios with fixtures."
            if totals.weighted_coverage_scored is not None
            else "."
        )
    )
    return {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": GRADIENT, "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "weighted coverage 0%", "color": GRADIENT[0]},
            {"label": "weighted coverage 100%", "color": GRADIENT[-1]},
            {"label": "fixtures pending", "color": PENDING_COLOR},
            {"label": "known gap (not emulated)", "color": GAP_COLOR},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "metadata": [
            {"name": "generated_at", "value": scorecard.generated_at.isoformat()},
            {"name": "tripline_version", "value": scorecard.tripline_version},
        ],
    }


def write_layer(scorecard: Scorecard, path: Path) -> dict[str, Any]:
    """Write the layer JSON to ``path`` and return it."""
    layer = build_layer(scorecard)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    return layer


def _technique_cell(coverage: TechniqueCoverage) -> dict[str, Any]:
    cell: dict[str, Any] = {
        "techniqueID": coverage.technique,
        "score": round(coverage.coverage * 100),
        "enabled": True,
        "showSubtechniques": "." in coverage.technique,
        "comment": (
            f"weight {coverage.weight}; coverage {coverage.coverage:.0%}; "
            f"scenarios: {', '.join(coverage.scenarios)}"
            + ("; fixtures pending" if coverage.pending else "")
        ),
        "metadata": [
            {"name": "weight", "value": str(coverage.weight)},
            {"name": "coverage", "value": f"{coverage.coverage:.2f}"},
            {"name": "rules", "value": ", ".join(coverage.rules)},
            {"name": "status", "value": "pending" if coverage.pending else "scored"},
        ],
    }
    if coverage.pending:
        cell["color"] = PENDING_COLOR
    return cell


def _gap_cell(technique: str, why: str) -> dict[str, Any]:
    return {
        "techniqueID": technique,
        "color": GAP_COLOR,
        "enabled": True,
        "showSubtechniques": True,
        "comment": f"KNOWN GAP: {why}",
        "metadata": [{"name": "status", "value": "known gap"}],
    }
