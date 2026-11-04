"""AWS plane: replay recorded CloudTrail detonations as tripline fixtures.

There is no live AWS account in this project. The cloud plane is built from two public
sources of *real* CloudTrail records:

* Stratus Red Team detonation logs (captured with Grimoire, Apache-2.0), one JSON array per
  attack technique, served from the Stratus repository.
* The flaws.cloud CloudTrail dataset published by Scott Piper (Summit Route), a tarball of
  gzip'd CloudTrail digest files from a deliberately vulnerable account.

:func:`replay_records` does what a live emulation would do to make telemetry attributable:
it rebases every ``eventTime`` so the oldest record lands at ``base_time`` with relative
offsets preserved, and appends ``tripline/<run-guid>`` to ``userAgent`` - the same trick
Grimoire uses to find its own events in CloudTrail.
"""

from __future__ import annotations

import gzip
import json
import tarfile
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tripline.models import Event

RUN_GUID_PREFIX = "tripline/"
EVENT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

RecordFilter = Callable[[Event], bool]


def new_run_guid() -> str:
    """A fresh run identifier (UUID4)."""
    return str(uuid.uuid4())


def load_stratus_log(path: Path) -> list[Event]:
    """Load a Stratus Red Team ``docs/detonation-logs/*.json`` file (a JSON array)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of CloudTrail records")
    return [_require_record(path, item) for item in data]


def iter_flaws_records(tar_path: Path) -> Iterator[Event]:
    """Stream CloudTrail records out of the flaws.cloud tarball without extracting it."""
    with tarfile.open(tar_path) as archive:
        for member in sorted(archive.getmembers(), key=lambda m: m.name):
            if not member.isfile() or not member.name.endswith(".json.gz"):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            with gzip.open(handle, "rt", encoding="utf-8") as text:
                payload = json.load(text)
            for item in payload.get("Records", []):
                yield _require_record(Path(member.name), item)


def select(
    records: Iterable[Event], predicate: RecordFilter, *, limit: int | None = None
) -> list[Event]:
    """Keep records matching ``predicate`` in original order, optionally capped at ``limit``."""
    chosen: list[Event] = []
    for record in records:
        if predicate(record):
            chosen.append(record)
            if limit is not None and len(chosen) >= limit:
                break
    return chosen


def select_many(
    records: Iterable[Event], quotas: Mapping[str, tuple[RecordFilter, int]]
) -> dict[str, list[Event]]:
    """Fill several named quotas in one pass; stops as soon as every quota is met.

    One pass matters for the flaws.cloud tarball (~2 million records): each predicate gets
    the record in turn and a record may satisfy several quotas.
    """
    chosen: dict[str, list[Event]] = {name: [] for name in quotas}
    for record in records:
        for name, (predicate, limit) in quotas.items():
            if len(chosen[name]) < limit and predicate(record):
                chosen[name].append(record)
        if all(len(chosen[name]) >= limit for name, (_, limit) in quotas.items()):
            break
    return chosen


def replay_records(
    records: list[Event], *, run_guid: str, base_time: datetime | None = None
) -> list[Event]:
    """Rebase timestamps and tag every record with the run GUID.

    Records are returned sorted by their (rebased) ``eventTime``. Original records are not
    mutated. Records without a parseable ``eventTime`` keep their value untouched.
    """
    base = (base_time or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    times = [t for t in (_parse_time(r) for r in records) if t is not None]
    origin = min(times) if times else base
    replayed: list[Event] = []
    for record in records:
        copy: Event = json.loads(json.dumps(record))
        when = _parse_time(record)
        if when is not None:
            copy["eventTime"] = (base + (when - origin)).strftime(EVENT_TIME_FORMAT)
        agent = str(copy.get("userAgent") or "").strip()
        tag = f"{RUN_GUID_PREFIX}{run_guid}"
        copy["userAgent"] = f"{agent} {tag}".strip()
        replayed.append(copy)
    replayed.sort(key=lambda r: str(r.get("eventTime", "")))
    return replayed


def run_guid_of(event: Event) -> str | None:
    """Extract the tripline run GUID from a replayed record's ``userAgent``."""
    agent = str(event.get("userAgent") or "")
    for token in agent.split():
        if token.startswith(RUN_GUID_PREFIX):
            return token[len(RUN_GUID_PREFIX) :]
    return None


def time_window(records: list[Event]) -> tuple[str, str] | None:
    """Earliest and latest ``eventTime`` as ISO strings, or ``None`` when absent."""
    times = [t for t in (_parse_time(r) for r in records) if t is not None]
    if not times:
        return None
    return min(times).strftime(EVENT_TIME_FORMAT), max(times).strftime(EVENT_TIME_FORMAT)


def _parse_time(record: Event) -> datetime | None:
    raw = record.get("eventTime")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, EVENT_TIME_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def _require_record(path: Path, item: Any) -> Event:
    if not isinstance(item, dict) or "eventName" not in item or "eventSource" not in item:
        raise ValueError(f"{path}: item is not a CloudTrail record")
    return item
