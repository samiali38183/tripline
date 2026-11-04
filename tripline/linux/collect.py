"""Linux plane: turn a raw auditd log into per-scenario NDJSON fixtures.

The emulation workflow (``.github/workflows/emulate-linux.yml``) runs Atomic Red Team tests on an
``ubuntu-latest`` runner with auditd rules for ``execve`` and the cron directories. Around every
test it executes a *marker* command::

    sh -c "true tripline-marker <run-guid> <test-guid> start|end"

so the audit log itself carries the attribution. :func:`collect` parses the log, merges the
records of one audit event (SYSCALL + EXECVE + PATH + CWD + PROCTITLE share a serial), slices the
stream between markers, and writes ``fixtures/linux/<scenario>/run.ndjson`` for every scenario
whose ``atomic_tests`` were seen, plus a ``manifest.json``.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from tripline.events import write_ndjson, write_text_lf
from tripline.models import Event, Plane, Scenario

MARKER = "tripline-marker"
_RECORD = re.compile(
    r"^type=(?P<type>\w+) msg=audit\((?P<ts>[\d.]+):(?P<serial>\d+)\):?\s*(?P<body>.*)$"
)
_KV = re.compile(r'([\w\[\]\-]+)=("[^"]*"|\S+)')
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")
_ARG = re.compile(r"^a\d+(?:\[\d+\])?$")


@dataclass
class _Pending:
    serial: str
    timestamp: str
    records: list[tuple[str, dict[str, str]]] = field(default_factory=list)


def _decode(key: str, raw: str) -> str:
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if (_ARG.match(key) or key == "proctitle") and _HEX.match(raw):
        text = bytes.fromhex(raw).decode("utf-8", errors="replace")
        return text.replace("\x00", " ").rstrip()
    return raw


def parse_records(lines: Iterable[str]) -> list[Event]:
    """Parse raw ``audit.log`` lines into one merged event per audit serial.

    The merged event keeps every SYSCALL field (``exe``, ``comm``, ``key``, ``syscall`` ...), the
    EXECVE arguments ``a0..aN`` (hex-decoded), ``cwd``, decoded ``proctitle`` and a ``paths`` list.
    ``type`` is ``EXECVE`` when an EXECVE record exists, otherwise the SYSCALL type, so the
    logsource router can classify it. ``TargetFilename`` is the first ``CREATE`` path, if any.
    """
    pending: OrderedDict[str, _Pending] = OrderedDict()
    for line in lines:
        match = _RECORD.match(line.strip())
        if not match:
            continue
        serial = match["serial"]
        entry = pending.get(serial)
        if entry is None:
            stamp = datetime.fromtimestamp(float(match["ts"]), tz=UTC)
            entry = _Pending(
                serial=serial, timestamp=stamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            )
            pending[serial] = entry
        fields = {k: _decode(k, v) for k, v in _KV.findall(match["body"])}
        entry.records.append((match["type"], fields))
    return [_merge(p) for p in pending.values()]


def _merge(entry: _Pending) -> Event:
    event: Event = {"timestamp": entry.timestamp, "serial": entry.serial, "type": "SYSCALL"}
    paths: list[dict[str, str]] = []
    args: dict[str, str] = {}
    types: list[str] = []
    for rtype, fields in entry.records:
        types.append(rtype)
        if rtype == "PATH":
            paths.append(fields)
        elif rtype == "EXECVE":
            args.update({k: v for k, v in fields.items() if _ARG.match(k)})
            event["argc"] = fields.get("argc")
        elif rtype in {"SYSCALL", "CWD", "PROCTITLE", "USER_CMD"}:
            event.update(fields)
        else:
            other = event.setdefault("other", {})
            if isinstance(other, dict):
                other[rtype] = fields
    if args:
        event["type"] = "EXECVE"
        event.update(_join_chunks(args))
    elif "SYSCALL" not in types and types:
        event["type"] = types[0]
    if paths:
        event["paths"] = paths
        created = next(
            (p["name"] for p in paths if p.get("nametype") == "CREATE" and "name" in p), None
        )
        if created:
            event["TargetFilename"] = created
    event["record_types"] = sorted(set(types))
    return event


def _join_chunks(args: dict[str, str]) -> dict[str, str]:
    """``a1[0]``, ``a1[1]`` (long arguments split by the kernel) -> ``a1``."""
    joined: dict[str, str] = {}
    for key in sorted(args, key=_arg_sort_key):
        base = key.split("[")[0]
        joined[base] = joined.get(base, "") + args[key]
    return joined


def _arg_sort_key(key: str) -> tuple[int, int]:
    num = int(re.match(r"a(\d+)", key).group(1))  # type: ignore[union-attr]
    chunk = int(key[key.index("[") + 1 : -1]) if "[" in key else 0
    return num, chunk


def command_line(event: Event) -> str:
    """Join ``a0..aN`` of a merged EXECVE event."""
    keys = sorted((k for k in event if re.fullmatch(r"a\d+", k)), key=lambda k: int(k[1:]))
    return " ".join(str(event[k]) for k in keys)


@dataclass(frozen=True, slots=True)
class Marker:
    """A parsed ``tripline-marker`` command."""

    run_guid: str
    test_guid: str
    phase: str


def marker_of(event: Event) -> Marker | None:
    """Return the marker if this event is a ``tripline-marker`` execution, else ``None``."""
    if event.get("type") != "EXECVE":
        return None
    match = re.search(rf"{MARKER} (\S+) (\S+) (start|end)\b", command_line(event))
    if not match:
        return None
    return Marker(run_guid=match[1], test_guid=match[2], phase=match[3])


def slice_by_markers(events: list[Event]) -> dict[str, list[Event]]:
    """Group events by Atomic test GUID using the start/end markers; markers are dropped."""
    buckets: dict[str, list[Event]] = {}
    current: Marker | None = None
    for event in events:
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
    log_lines: Iterable[str],
    scenarios: list[Scenario],
    fixtures_dir: Path,
    *,
    run_guid: str,
    source: str,
) -> dict[str, Path]:
    """Write ``fixtures/linux/<scenario>/run.ndjson`` + ``manifest.json`` per Linux scenario seen.

    Returns ``{scenario_id: fixture_path}``. Scenarios whose tests produced no events are skipped
    (the caller decides whether that is an error).
    """
    buckets = slice_by_markers(parse_records(log_lines))
    written: dict[str, Path] = {}
    for scenario in scenarios:
        if scenario.plane is not Plane.LINUX:
            continue
        events = [e for guid in scenario.emulation.atomic_tests for e in buckets.get(guid, [])]
        if not events:
            continue
        out_dir = fixtures_dir / scenario.id
        target = out_dir / "run.ndjson"
        write_ndjson(target, events)
        manifest = {
            "scenario_id": scenario.id,
            "run_guid": run_guid,
            "source": source,
            "events": len(events),
            "atomic_tests": {
                guid: len(buckets.get(guid, [])) for guid in scenario.emulation.atomic_tests
            },
            "execve_events": sum(1 for e in events if e.get("type") == "EXECVE"),
            "created_files": sorted(
                {str(e["TargetFilename"]) for e in events if "TargetFilename" in e}
            ),
            "time_window": [events[0]["timestamp"], events[-1]["timestamp"]],
        }
        write_text_lf(out_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")
        written[scenario.id] = target
    return written
