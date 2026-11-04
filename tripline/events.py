"""NDJSON event I/O and field access helpers.

Events are plain dictionaries. Windows events are flat (Sysmon ``EventData`` fields promoted
to the top level, plus ``Channel`` and ``EventID``), auditd events are flat key/value records,
CloudTrail records are nested JSON exactly as AWS emits them - so field lookup must support
dotted paths (``userIdentity.type``) as well as literal keys that contain a dot.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from tripline.models import Event

_MISSING = object()


def read_ndjson(path: Path) -> list[Event]:
    """Load an NDJSON file, skipping blank lines. Raises on malformed JSON with the line number."""
    events: list[Event] = []
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON ({exc.msg})") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{lineno}: expected a JSON object")
            events.append(record)
    return events


def write_ndjson(path: Path, events: Iterable[Event]) -> int:
    """Write events as one compact JSON object per line. Returns the number written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True, ensure_ascii=False))
            handle.write("\n")
            count += 1
    return count


def get_field(event: Event, field: str) -> Any:
    """Resolve ``field`` against ``event``.

    Resolution order: literal key, then dotted path through nested dicts. When a path segment
    lands on a list (CloudTrail ``requestParameters.*.Grant`` is a list of grants) the
    remaining path is resolved against every element and the results are flattened, so a
    rule written as ``Grant.Grantee.URI|contains: AllUsers`` sees all grantees. Returns
    ``None`` when the path does not exist so callers can treat "absent" and ``null`` alike,
    which is how Sigma's ``field: null`` is defined.
    """
    if field in event:
        return event[field]
    return _resolve(event, field.split("."))


def _resolve(current: Any, parts: list[str]) -> Any:
    for index, part in enumerate(parts):
        if isinstance(current, list):
            values = [_resolve(item, parts[index:]) for item in current]
            flat = [v for v in values if v is not None]
            return flat or None
        if not isinstance(current, dict):
            return None
        current = current.get(part, _MISSING)
        if current is _MISSING:
            return None
    return current


def has_field(event: Event, field: str) -> bool:
    """True when ``field`` exists (even with a ``null`` value), used for ``|exists``."""
    if field in event:
        return True
    current: Any = event
    parts = field.split(".")
    for part in parts[:-1]:
        if not isinstance(current, dict):
            return False
        current = current.get(part, _MISSING)
        if current is _MISSING:
            return False
    return isinstance(current, dict) and parts[-1] in current


def iter_leaf_values(event: Event) -> Iterator[Any]:
    """Yield every scalar leaf in a (possibly nested) event; used for keyword searches."""
    stack: list[Any] = [event]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        else:
            yield node


def set_field(event: Event, field: str, value: Any) -> Event:
    """Return a shallow-copied event with ``field`` (dotted path allowed) set to ``value``."""
    updated = dict(event)
    if field in updated or "." not in field:
        updated[field] = value
        return updated
    parts = field.split(".")
    cursor = updated
    for part in parts[:-1]:
        child = cursor.get(part)
        child = dict(child) if isinstance(child, dict) else {}
        cursor[part] = child
        cursor = child
    cursor[parts[-1]] = value
    return updated
