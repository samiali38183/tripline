"""Benign corpus: record, sanitize and replay normal activity to count false positives.

A scenario pass only shows that a rule fires on the attack. This module measures the other half:
every compiled rule is replayed over telemetry recorded while ordinary work (package installs,
git, a build and test run, ``chmod 644/755``, idle cron-style activity) ran on a runner with the
same auditd setup as ``emulate-linux.yml``. A rule that matches a benign event is reported, never
hidden.

The corpus is Linux only today, so only rules whose logsource applies to auditd events are
evaluated; Windows and AWS rules are listed as ``not evaluated`` instead of as clean.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tripline.engine.rules import RuleSet, evaluate
from tripline.events import read_ndjson, write_ndjson, write_text_lf
from tripline.linux.collect import command_line, parse_records, slice_by_markers
from tripline.models import BenignReport, BenignRuleResult, Event

BENIGN_TEST_GUID = "benign"
"""The ``<test-guid>`` slot of the tripline-marker command that brackets the benign workload."""
MAX_CORPUS_BYTES = 5_000_000
CORPUS_FILE = "run.ndjson"
EXAMPLES_PER_RULE = 3

_PATH_KEEP = ("name", "nametype", "mode")
_DROP_KEYS = frozenset({"hostname", "node", "addr", "terminal", "exe_hash"})

_REDACTIONS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        "[REDACTED]",
    ),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED]"),
    ("bearer", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 [REDACTED]"),
    (
        "credential_assignment",
        re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)=\S+"),
        r"\1=[REDACTED]",
    ),
    ("url_credentials", re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "user@example.invalid"),
    (
        "ipv4",
        re.compile(
            r"\b(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
            r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        "192.0.2.1",
    ),
]


@dataclass(slots=True)
class Sanitizer:
    """Strip hostnames and secret-shaped strings from events; count what was removed."""

    hosts: tuple[str, ...] = ()
    counts: Counter[str] = field(default_factory=Counter)

    def event(self, event: Event) -> Event:
        """Return a sanitized copy of ``event`` (noise fields dropped, strings redacted)."""
        cleaned: dict[str, Any] = {}
        for key, value in event.items():
            if key in _DROP_KEYS:
                self.counts[f"dropped_field:{key}"] += 1
                continue
            if key == "paths" and isinstance(value, list):
                value = [
                    {k: p[k] for k in _PATH_KEEP if k in p} for p in value if isinstance(p, dict)
                ]
            cleaned[key] = self._value(value)
        return cleaned

    def _value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._text(value)
        if isinstance(value, list):
            return [self._value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._value(v) for k, v in value.items()}
        return value

    def _text(self, text: str) -> str:
        for host in self.hosts:
            if host and host in text:
                self.counts["hostname"] += text.count(host)
                text = text.replace(host, "runner-host")
        for name, pattern, replacement in _REDACTIONS:
            text, n = pattern.subn(replacement, text)
            if n:
                self.counts[name] += n
        return text


def find_secret_patterns(events: Iterable[Event]) -> list[str]:
    """Scan events for strings that the sanitizer would still change; used by tests and CI."""
    findings: list[str] = []
    for index, event in enumerate(events):
        text = json.dumps(event, ensure_ascii=False)
        for name, pattern, replacement in _REDACTIONS:
            for match in pattern.finditer(text):
                if match.group(0) != pattern.sub(replacement, match.group(0)):
                    findings.append(f"event {index}: {name}")
    return findings


def collect_benign(
    log_lines: Iterable[str],
    out_dir: Path,
    *,
    run_guid: str,
    source: str,
    workload: str,
    hosts: tuple[str, ...] = (),
    max_bytes: int = MAX_CORPUS_BYTES,
) -> Path:
    """Slice the benign window out of an auditd log, sanitize it and write the corpus.

    Writes ``<out_dir>/run.ndjson`` and ``<out_dir>/manifest.json``. Raises ``ValueError`` when no
    events fall in the window, when sanitization leaves a secret-shaped string behind, or when the
    corpus would exceed ``max_bytes``.
    """
    buckets = slice_by_markers(parse_records(log_lines), run_guid=run_guid)
    raw = buckets.get(BENIGN_TEST_GUID, [])
    if not raw:
        raise ValueError(f"no events between the benign markers for run {run_guid}")
    sanitizer = Sanitizer(hosts=hosts)
    events = [sanitizer.event(e) for e in raw]
    leftovers = find_secret_patterns(events)
    if leftovers:
        raise ValueError(f"secret-shaped strings survived sanitization: {leftovers[:5]}")
    target = out_dir / CORPUS_FILE
    write_ndjson(target, events)
    size = target.stat().st_size
    if size > max_bytes:
        target.unlink()
        raise ValueError(f"benign corpus is {size} bytes, over the {max_bytes} byte limit")
    manifest = {
        "kind": "benign",
        "plane": "linux",
        "telemetry": "auditd (execve + cron directory watches, same rules as emulate-linux.yml)",
        "run_guid": run_guid,
        "source": source,
        "workload": workload,
        "events": len(events),
        "execve_events": sum(1 for e in events if e.get("type") == "EXECVE"),
        "bytes": size,
        "time_window": [events[0]["timestamp"], events[-1]["timestamp"]],
        "sanitization": {
            "dropped_event_fields": sorted(_DROP_KEYS),
            "path_fields_kept": list(_PATH_KEEP),
            "redactions": dict(sorted(sanitizer.counts.items())),
            "kept_on_purpose": "generic runner account names (runner, root) and public repo URLs",
        },
    }
    write_text_lf(out_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return target


def load_corpus(directory: Path) -> list[Event]:
    """Read every ``*.ndjson`` under ``directory``; empty list when it does not exist."""
    if not directory.is_dir():
        return []
    events: list[Event] = []
    for path in sorted(directory.rglob("*.ndjson")):
        events.extend(read_ndjson(path))
    return events


def replay_benign(rules: RuleSet, events: list[Event]) -> BenignReport:
    """Evaluate every compiled rule over the benign ``events``.

    A rule with zero applicable events (its logsource never matches the corpus) is reported as
    not evaluated. A rule that matches at least one event is a false positive and keeps up to
    ``EXAMPLES_PER_RULE`` command lines as evidence.
    """
    results: list[BenignRuleResult] = []
    for rule in rules.rules:
        applicable = 0
        matched = 0
        examples: list[str] = []
        for event in events:
            verdict = evaluate(rule, event)
            if verdict is None:
                continue
            applicable += 1
            if verdict:
                matched += 1
                if len(examples) < EXAMPLES_PER_RULE:
                    examples.append(_describe(event))
        results.append(
            BenignRuleResult(
                rule_id=rule.id,
                title=rule.title,
                applicable=applicable,
                matched=matched,
                examples=examples,
            )
        )
    return BenignReport(events=len(events), rules=results)


def _describe(event: Event) -> str:
    text = command_line(event) if event.get("type") == "EXECVE" else ""
    if not text:
        text = str(event.get("TargetFilename") or event.get("proctitle") or event.get("exe") or "")
    return text[:200]
