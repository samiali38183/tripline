"""Windows plane: slice an exported winlog NDJSON stream into per-scenario fixtures.

The emulation workflow (``.github/workflows/emulate-windows.yml``) runs Atomic Red Team tests on a
``windows-latest`` runner with Sysmon, Security process auditing (4688 with command line, 4698
task creation) and PowerShell script-block logging enabled. Around every test it executes a
*marker* process::

    cmd.exe /c "echo tripline-marker <run-guid> <test-guid> start|end"

which shows up as Sysmon EID 1 (and Security 4688) with the marker in ``CommandLine``.
``scripts/windows/Export-TriplineEvents.ps1`` exports the three channels into one NDJSON file in
the Fluent Bit ``winlog`` shape (``Channel``, ``EventID``, ``TimeCreated``, EventData promoted to
the top level) which :func:`collect` orders by time, slices between markers, and writes to
``fixtures/windows/<scenario>/run.ndjson`` plus a ``manifest.json``.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from tripline.events import write_ndjson, write_text_lf
from tripline.logsource import normalize
from tripline.models import Event, Plane, Scenario

MARKER = "tripline-marker"
_MARKER_RE = re.compile(rf"{MARKER} (\S+) (\S+) (start|end)\b")


@dataclass(frozen=True, slots=True)
class Marker:
    """A parsed ``tripline-marker`` process creation."""

    run_guid: str
    test_guid: str
    phase: str


def marker_of(event: Event) -> Marker | None:
    """Return the marker if this event is a marker process creation, else ``None``.

    Only process-creation events (Sysmon 1, Security 4688) count; a PowerShell 4104 script block
    that *mentions* the marker (the workflow loop itself) is not a boundary.
    """
    event = normalize(event)
    event_id = event.get("EventID")
    channel = str(event.get("Channel"))
    if not (
        (channel == "Microsoft-Windows-Sysmon/Operational" and event_id == 1)
        or (channel == "Security" and event_id == 4688)
    ):
        return None
    match = _MARKER_RE.search(str(event.get("CommandLine") or ""))
    if not match:
        return None
    return Marker(run_guid=match[1], test_guid=match[2], phase=match[3])


def _sort_key(event: Event) -> tuple[str, int]:
    record = event.get("RecordNumber")
    return str(event.get("TimeCreated") or ""), int(record) if isinstance(record, int) else 0


def slice_by_markers(events: list[Event]) -> dict[str, list[Event]]:
    """Group events by Atomic test GUID using the start/end markers; markers are dropped.

    Events are ordered by ``TimeCreated`` across channels first, so Security and PowerShell
    records that land between a Sysmon start and end marker are attributed correctly. Both
    Sysmon and Security may record the same marker; a repeated ``start`` just re-asserts the
    current test and a second ``end`` after the bucket closed is ignored.
    """
    buckets: dict[str, list[Event]] = {}
    current: Marker | None = None
    for event in sorted(events, key=_sort_key):
        marker = marker_of(event)
        if marker is not None:
            current = marker if marker.phase == "start" else None
            continue
        if current is not None:
            tagged = dict(event)
            tagged["tripline"] = {"run_guid": current.run_guid, "atomic_test": current.test_guid}
            buckets.setdefault(current.test_guid, []).append(tagged)
    return buckets


def collect(
    events: list[Event],
    scenarios: list[Scenario],
    fixtures_dir: Path,
    *,
    run_guid: str,
    source: str,
) -> dict[str, Path]:
    """Write ``fixtures/windows/<scenario>/run.ndjson`` + ``manifest.json`` per scenario seen.

    Returns ``{scenario_id: fixture_path}``. Scenarios whose tests produced no events are skipped.
    """
    buckets = slice_by_markers(events)
    written: dict[str, Path] = {}
    for scenario in scenarios:
        if scenario.plane is not Plane.WINDOWS:
            continue
        picked = [e for guid in scenario.emulation.atomic_tests for e in buckets.get(guid, [])]
        if not picked:
            continue
        out_dir = fixtures_dir / scenario.id
        target = out_dir / "run.ndjson"
        write_ndjson(target, picked)
        channels = Counter(f"{e.get('Channel')}:{normalize(e).get('EventID')}" for e in picked)
        manifest = {
            "scenario_id": scenario.id,
            "run_guid": run_guid,
            "source": source,
            "events": len(picked),
            "atomic_tests": {
                guid: len(buckets.get(guid, [])) for guid in scenario.emulation.atomic_tests
            },
            "events_by_channel_and_id": dict(sorted(channels.items())),
            "time_window": [
                str(picked[0].get("TimeCreated")),
                str(picked[-1].get("TimeCreated")),
            ],
        }
        write_text_lf(out_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")
        written[scenario.id] = target
    return written
