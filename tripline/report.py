"""Render a scorecard as a self-contained HTML report and an SVG coverage badge.

Both outputs are built from ``scorecard.json`` alone, like the Navigator layer and the Markdown
page, so CI can publish them without replaying anything twice. The HTML has no external
scripts, stylesheets or fonts: it opens from disk, from a CI artifact, or from GitHub Pages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

from jinja2 import Environment, PackageLoader, select_autoescape

from tripline.events import write_text_lf
from tripline.models import (
    Plane,
    ScenarioScore,
    ScenarioStatus,
    Scorecard,
    describe_outcome,
)

TACTICS: list[tuple[str, str]] = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("stealth", "Stealth"),
    ("defense-impairment", "Defense Impairment"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]
"""ATT&CK Enterprise v20 tactics in matrix order (short name, display name).

ATT&CK v19 split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112); the order
and names match the ``x-mitre-matrix`` object in enterprise-attack-20.1.json.
"""

LEGACY_TACTICS: dict[str, str] = {"defense-evasion": "Defense Evasion (ATT&CK v18 and earlier)"}
"""Tactic short names that no longer exist, so scorecards written before 0.3.0 still render."""

PLANE_LABEL = {Plane.AWS: "AWS", Plane.LINUX: "Linux", Plane.WINDOWS: "Windows"}
UNKNOWN_TACTIC = "Unmapped"


@dataclass
class TacticColumn:
    """One column of the matrix: a tactic and the scenarios mapped to it."""

    key: str
    label: str
    scenarios: list[ScenarioScore] = field(default_factory=list)


@dataclass
class WeightSplit:
    """Prevalence weight points by scenario status (the bar under the headline)."""

    passed: int
    failed: int
    pending: int

    @property
    def total(self) -> int:
        """All weight points."""
        return self.passed + self.failed + self.pending

    def pct(self, part: int) -> float:
        """``part`` as a percentage of the total, for bar segment widths."""
        return 100.0 * part / self.total if self.total else 0.0


def tactic_columns(card: Scorecard) -> tuple[list[TacticColumn], list[str]]:
    """Group scenarios into tactic columns in kill-chain order.

    Returns the populated columns and the display names of tactics with no scenario, so the
    report can say which parts of the matrix are empty instead of hiding them. Scenarios whose
    tactic is empty (older scorecards) or unknown land in a trailing "Unmapped" column.
    """
    columns = {key: TacticColumn(key, label) for key, label in TACTICS}
    legacy = {key: TacticColumn(key, label) for key, label in LEGACY_TACTICS.items()}
    extra = TacticColumn("unmapped", UNKNOWN_TACTIC)
    for scenario in card.scenarios:
        (columns.get(scenario.tactic) or legacy.get(scenario.tactic) or extra).scenarios.append(
            scenario
        )
    for column in [*columns.values(), *legacy.values(), extra]:
        column.scenarios.sort(key=lambda s: (-s.weight, s.technique, s.scenario_id))
    populated = [c for c in [*columns.values(), *legacy.values()] if c.scenarios]
    if extra.scenarios:
        populated.append(extra)
    empty = [c.label for c in columns.values() if not c.scenarios]
    return populated, empty


def weight_split(card: Scorecard) -> WeightSplit:
    """Sum prevalence weights by status."""

    def total(status: ScenarioStatus) -> int:
        return sum(s.weight for s in card.scenarios if s.status is status)

    return WeightSplit(
        passed=total(ScenarioStatus.PASSED),
        failed=total(ScenarioStatus.FAILED),
        pending=total(ScenarioStatus.PENDING),
    )


def render_html(card: Scorecard, *, title: str = "tripline coverage report") -> str:
    """Render the scorecard as one HTML document (inline CSS, no JavaScript)."""
    env = Environment(
        loader=PackageLoader("tripline", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    columns, empty = tactic_columns(card)
    rule_titles = {r.rule_id: r.title for r in card.rules}
    return env.get_template("report.html.j2").render(
        title=title,
        card=card,
        totals=card.totals,
        columns=columns,
        empty_tactics=empty,
        split=weight_split(card),
        planes=PLANE_LABEL,
        rule_titles=rule_titles,
        tactic_labels={**dict(TACTICS), **LEGACY_TACTICS},
        Status=ScenarioStatus,
        describe=describe_outcome,
    )


def write_html(card: Scorecard, path: Path) -> None:
    """Write :func:`render_html` output to ``path`` with LF line endings."""
    write_text_lf(path, render_html(card))


# --------------------------------------------------------------------------- badge

BADGE_COLORS = [(0.8, "#2e7d32"), (0.4, "#9e7c00"), (0.0, "#c62828")]
"""Value colour by weighted coverage: >= 80 % green, >= 40 % amber, else red."""


def _text_width(text: str) -> int:
    # Approximate Verdana 11px advance widths; good enough for a badge that is never wider
    # than ~30 characters.
    narrow = set("fijlrt1 .,:;|!'()")
    wide = set("mwMW%@")
    width = 0.0
    for ch in text:
        width += 4.0 if ch in narrow else 9.5 if ch in wide else 7.0
    return int(width + 0.5)


def render_badge(card: Scorecard, *, label: str = "weighted coverage") -> str:
    """Render a flat SVG badge: ``label | NN%`` coloured by weighted coverage of all scenarios."""
    value = card.totals.weighted_coverage
    text = f"{value:.0%}"
    color = next(c for threshold, c in BADGE_COLORS if value >= threshold)
    lw = _text_width(label) + 12
    vw = _text_width(text) + 12
    width = lw + vw
    aria = escape(f"{label}: {text}")
    lab, txt = escape(label), escape(text)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" '
        f'aria-label="{aria}">\n'
        f"  <title>{aria}</title>\n"
        f'  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" '
        f'stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>\n'
        f'  <clipPath id="r"><rect width="{width}" height="20" rx="3" fill="#fff"/></clipPath>\n'
        f'  <g clip-path="url(#r)">\n'
        f'    <rect width="{lw}" height="20" fill="#555"/>\n'
        f'    <rect x="{lw}" width="{vw}" height="20" fill="{color}"/>\n'
        f'    <rect width="{width}" height="20" fill="url(#s)"/>\n'
        f"  </g>\n"
        f'  <g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">\n'
        f'    <text x="{lw / 2:.1f}" y="15" fill="#010101" fill-opacity=".3">{lab}</text>\n'
        f'    <text x="{lw / 2:.1f}" y="14">{lab}</text>\n'
        f'    <text x="{lw + vw / 2:.1f}" y="15" fill="#010101" fill-opacity=".3">{txt}</text>\n'
        f'    <text x="{lw + vw / 2:.1f}" y="14">{txt}</text>\n'
        f"  </g>\n"
        f"</svg>\n"
    )


def write_badge(card: Scorecard, path: Path) -> None:
    """Write :func:`render_badge` output to ``path``."""
    write_text_lf(path, render_badge(card))
