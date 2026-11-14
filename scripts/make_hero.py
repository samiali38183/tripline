"""Render docs/img/hero.png from the committed fixtures and docs/scorecard.json.

Every number in the image is computed here, not typed in:
  * the two attack events come from fixtures/linux/t1548-001-setuid-setgid (events run by /usr/bin/chmod)
  * "stock rule" and "replacement rule" results come from evaluating both Sigma rules on those events
  * coverage figures come from docs/scorecard.json

Run from the repo root:  python scripts/make_hero.py   (needs matplotlib and the dev install)
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

from tripline.engine.rules import evaluate, load_rules
from tripline.logsource import normalize
from tripline.replay import load_fixture_events
from tripline.scenarios import load_scenarios

ROOT = Path(__file__).resolve().parent.parent
STOCK = "c21c4eaa-ba2e-419a-92b2-8371703cbe21"  # SigmaHQ "Setuid and Setgid", vendored unmodified
MINE = "7f3c2b1a-6d4e-4a9b-9c8d-1e2f3a4b5c6d"  # tripline replacement rule

# Shared look across samiali38183 repos: light background, dark text, large type.
TEXT, MUTED, LINE, PANEL = "#111827", "#4b5563", "#d1d5db", "#f3f4f6"
GOOD, BAD, ACCENT = "#15803d", "#b91c1c", "#1d4ed8"
GOOD_BG, BAD_BG = "#dcfce7", "#fee2e2"
plt.rcParams["font.family"] = "DejaVu Sans"


def measure() -> dict:
    scen = {s.id: s for s in load_scenarios(ROOT / "scenarios")}["t1548-001-setuid-setgid"]
    events = load_fixture_events(scen, ROOT)
    by_id = {r.id: r for r in load_rules(ROOT / "rules" / "sigma").rules}
    attacks = [e for e in events if normalize(e).get("Image", "").endswith("/chmod")]
    cmds = [normalize(e)["CommandLine"] for e in attacks]
    stock = [bool(evaluate(by_id[STOCK], e)) for e in attacks]
    mine = [bool(evaluate(by_id[MINE], e)) for e in attacks]
    card = json.loads((ROOT / "docs" / "scorecard.json").read_text(encoding="utf-8"))
    total = sum(s["weight"] for s in card["scenarios"])
    passed = sum(s["weight"] for s in card["scenarios"] if s["status"] == "passed")
    vendored = sum(
        s["weight"]
        for s in card["scenarios"]
        if s["status"] == "passed" and not s["needs_authored_rule"]
    )
    return dict(
        cmds=cmds,
        stock=stock,
        mine=mine,
        total=total,
        passed=passed,
        vendored=vendored,
        n_scen=len(card["scenarios"]),
        version=card["tripline_version"],
    )


def box(ax, x, y, w, h, fc, ec=LINE, lw=1.5, r=1.2):
    ax.add_patch(
        FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}", fc=fc, ec=ec, lw=lw)
    )


def main() -> None:
    m = measure()
    fig = plt.figure(figsize=(9, 5.5), dpi=200, facecolor="white")
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 180)
    ax.set_ylim(0, 110)
    ax.axis("off")

    ax.text(
        6,
        101,
        "A published Sigma rule missed both real attacks",
        fontsize=20,
        fontweight="bold",
        color=TEXT,
        va="center",
    )
    ax.text(
        6,
        92,
        "tripline replays recorded attack telemetry through detection rules and fails the build on a miss.",
        fontsize=11.5,
        color=MUTED,
        va="center",
    )

    # Left panel: the two attack events against each rule
    box(ax, 6, 19, 92, 61, PANEL)
    ax.text(
        10,
        75,
        "The 2 real attack commands (T1548.001)",
        fontsize=10.5,
        color=TEXT,
        fontweight="bold",
        va="center",
    )
    rows = [
        ("SigmaHQ rule, as published", m["stock"]),
        ("Replacement rule from this repo", m["mine"]),
    ]
    for i, (name, res) in enumerate(rows):
        y = 64 - i * 24
        ax.text(10, y, name, fontsize=10, color=TEXT, va="center")
        ok_all = all(res)
        ax.text(
            94,
            y,
            f"{sum(res)} of {len(res)} caught",
            fontsize=11,
            fontweight="bold",
            color=GOOD if ok_all else BAD,
            va="center",
            ha="right",
        )
        for j, (cmd, ok) in enumerate(zip(m["cmds"], res)):
            x = 10 + j * 44
            box(ax, x, y - 14, 41, 10, GOOD_BG if ok else BAD_BG, ec=GOOD if ok else BAD, lw=1.6)
            ax.text(
                x + 2.5,
                y - 9,
                "caught" if ok else "MISSED",
                fontsize=10,
                color=GOOD if ok else BAD,
                fontweight="bold",
                va="center",
            )
            ax.text(
                x + 38.5,
                y - 9,
                cmd.split(" /")[0],
                fontsize=9,
                color=TEXT,
                va="center",
                ha="right",
                family="DejaVu Sans Mono",
            )

    # Right panel: weighted coverage
    box(ax, 104, 19, 70, 61, PANEL)
    ax.text(
        108,
        75,
        f"Weighted coverage, {m['n_scen']} scenarios",
        fontsize=10.5,
        color=TEXT,
        fontweight="bold",
        va="center",
    )
    bars = [
        ("Unmodified SigmaHQ rules", m["vendored"], "#6b7280"),
        ("Plus rules written here", m["passed"], ACCENT),
    ]
    for i, (label, val, col) in enumerate(bars):
        y = 64 - i * 24
        ax.text(108, y, label, fontsize=9.5, color=TEXT, va="center")
        box(ax, 108, y - 12, 62, 6, "white", lw=1.2, r=0.8)
        box(ax, 108, y - 12, 62 * val / m["total"], 6, col, ec=col, lw=0, r=0.8)
        ax.text(
            170,
            y,
            f"{round(100 * val / m['total'])}%",
            fontsize=15,
            color=col,
            fontweight="bold",
            va="center",
            ha="right",
        )
        ax.text(
            108, y - 15.5, f"{val} of {m['total']} points", fontsize=9, color=MUTED, va="center"
        )

    ax.text(
        6,
        14,
        'Why it missed: the rule looks for the literal text " chmod u+s", but the real test ran '
        '"chmod u+xs".',
        fontsize=10.5,
        color=TEXT,
        va="center",
    )
    ax.text(
        6,
        8.5,
        "A pass means every expected rule fired on recorded telemetry. Points are prevalence weights "
        "(docs/weights.md).",
        fontsize=8.8,
        color=MUTED,
        va="center",
    )
    ax.text(
        6,
        4,
        f"Source: fixtures/linux, docs/scorecard.json (tripline {m['version']}).  "
        "Reproduce: python scripts/make_hero.py",
        fontsize=8.8,
        color=MUTED,
        va="center",
    )

    out = ROOT / "docs" / "img" / "hero.png"
    fig.savefig(out, dpi=200, facecolor="white")
    from PIL import Image

    img = Image.open(out).convert("RGB")
    img.quantize(colors=64, dither=Image.Dither.NONE).save(out, optimize=True)  # small, flat colors
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
