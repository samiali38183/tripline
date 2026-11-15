"""Render docs/img/evidence.png: recorded telemetry kept apart from generated variants.

Numbers are computed here from the committed fixture and rules, not typed in.
Run from the repo root:  python scripts/make_evidence.py   (needs matplotlib and the dev install)
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from tripline.engine.rules import evaluate, load_rules
from tripline.replay import load_fixture_events
from tripline.robustness import run_sweep
from tripline.scenarios import load_scenarios

ROOT = Path(__file__).resolve().parent.parent
STOCK = "c21c4eaa-ba2e-419a-92b2-8371703cbe21"
MINE = "7f3c2b1a-6d4e-4a9b-9c8d-1e2f3a4b5c6d"
SID = "t1548-001-setuid-setgid"


def main() -> None:
    scenarios = load_scenarios(ROOT / "scenarios")
    rules = load_rules(ROOT / "rules" / "sigma")
    scen = {s.id: s for s in scenarios}[SID]
    events = load_fixture_events(scen, ROOT)
    execve = [e for e in events if e.get("type") == "EXECVE"]
    attack = [e for e in execve if e.get("exe") == "/usr/bin/chmod"]
    rec = {}
    for name, rid in (("replacement rule", MINE),):
        rule = rules.by_id(rid)
        rec[name] = sum(1 for e in attack if evaluate(rule, e) is True)
    sweep = run_sweep([scen], rules, ROOT)
    sc = sweep.scenarios[0]
    gen_mine = next(r for r in sc.rules if r.rule_id == MINE)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), gridspec_kw={"width_ratios": [2, 3]})
    ax = axes[0]
    ax.bar(list(rec), list(rec.values()), color=["#15803d"], width=0.4)
    ax.set_ylim(0, len(attack) * 1.2)
    ax.set_yticks(range(len(attack) + 1))
    ax.axhline(len(attack), color="#9ca3af", lw=0.8, ls="--")
    ax.set_ylabel("chmod attack events matched")
    ax.set_title(
        f"Recorded: {len(attack)} chmod events\n(of {len(execve)} execve, {len(events)} total)"
    )
    for i, v in enumerate(rec.values()):
        ax.text(i, v + 0.05, f"{v} of {len(attack)}", ha="center", fontweight="bold")
    ax = axes[1]
    ax.bar(["replacement rule"], [gen_mine.cmdline_caught], color="#1d4ed8", width=0.4)
    ax.axhline(gen_mine.cmdline_variants, color="#9ca3af", lw=0.8, ls="--")
    ax.set_ylim(0, gen_mine.cmdline_variants * 1.15)
    ax.set_ylabel("variants caught")
    ax.set_title(
        f"Generated: {gen_mine.cmdline_variants} spellings of the same command\n(not recorded)"
    )
    ax.text(
        0,
        gen_mine.cmdline_caught + 1.5,
        f"{gen_mine.cmdline_caught} of {gen_mine.cmdline_variants}",
        ha="center",
        fontweight="bold",
    )
    for a in axes:
        a.spines[["top", "right"]].set_visible(False)
    fig.text(
        0.01,
        0.01,
        "Note: generated variants are bare chmod events without 'chown root', so the SigmaHQ rule "
        "(which needs both in one command line) cannot match them; that is not a fair comparison.\n"
        "Reproduce: python scripts/make_evidence.py",
        fontsize=7.5,
        color="#4b5563",
        va="bottom",
    )
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    out = ROOT / "docs" / "img" / "evidence.png"
    fig.savefig(out, dpi=170, facecolor="white")
    print(f"wrote {out}", rec, gen_mine.cmdline_caught, gen_mine.cmdline_variants)


if __name__ == "__main__":
    main()
