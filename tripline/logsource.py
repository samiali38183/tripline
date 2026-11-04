"""Route raw telemetry to Sigma logsources.

This module is the field map between what collectors emit and what Sigma rules expect.
It is deliberately code, not configuration: the parity/fixture tests fail when an event
shape appears that no router understands, which is how schema drift is caught.

Supported shapes:

* **Windows** - Sysmon, Security and PowerShell channels with ``Channel``/``EventID`` and
  Sysmon ``EventData`` fields promoted to the top level (the shape Fluent Bit's ``winlog``
  input produces after ``Rename``/``Lift`` filters).
* **Linux** - auditd records as flat key/value pairs (``type``, ``exe``, ``a0``..``aN``,
  ``syscall``, ``key``). ``EXECVE`` records are additionally normalised so rules written for
  ``category: process_creation`` (``Image``/``CommandLine``) can match them.
* **AWS** - CloudTrail records exactly as delivered (``eventSource``, ``eventName``, nested
  ``userIdentity``...).
"""

from __future__ import annotations

from dataclasses import dataclass

from sigma.rule import SigmaLogSource

from tripline.models import Event, Plane

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

SYSMON_CATEGORIES: dict[int, str] = {
    1: "process_creation",
    3: "network_connection",
    7: "image_load",
    8: "create_remote_thread",
    10: "process_access",
    11: "file_event",
    12: "registry_add",
    13: "registry_set",
    17: "pipe_created",
    22: "dns_query",
    23: "file_delete",
}

POWERSHELL_CATEGORIES: dict[int, str] = {
    4103: "ps_module",
    4104: "ps_script",
}

AUDITD_RECORD_TYPES = frozenset({"EXECVE", "SYSCALL", "PATH", "PROCTITLE", "CWD", "USER_CMD"})


@dataclass(frozen=True, slots=True)
class LogSource:
    """A concrete (product, category, service) triple an event satisfies."""

    product: str
    category: str | None = None
    service: str | None = None

    def satisfies(self, rule_logsource: SigmaLogSource) -> bool:
        """True when every attribute the rule specifies equals ours."""
        return (
            (rule_logsource.product is None or rule_logsource.product == self.product)
            and (rule_logsource.category is None or rule_logsource.category == self.category)
            and (rule_logsource.service is None or rule_logsource.service == self.service)
        )

    def __str__(self) -> str:
        """Render as ``product=... category=... service=...`` for scorecards."""
        parts = [f"product={self.product}"]
        if self.category:
            parts.append(f"category={self.category}")
        if self.service:
            parts.append(f"service={self.service}")
        return " ".join(parts)


def plane_of(event: Event) -> Plane | None:
    """Infer the telemetry plane from the event shape, or ``None`` if unrecognised."""
    if "eventSource" in event and "eventName" in event:
        return Plane.AWS
    if "Channel" in event and "EventID" in event:
        return Plane.WINDOWS
    if isinstance(event.get("type"), str) and event["type"] in AUDITD_RECORD_TYPES:
        return Plane.LINUX
    return None


def classify(event: Event) -> frozenset[LogSource]:
    """Return every Sigma logsource the event can be evaluated under (empty if unknown)."""
    plane = plane_of(event)
    if plane is Plane.AWS:
        return frozenset({LogSource(product="aws", service="cloudtrail")})
    if plane is Plane.WINDOWS:
        return _classify_windows(event)
    if plane is Plane.LINUX:
        return _classify_linux(event)
    return frozenset()


def _classify_windows(event: Event) -> frozenset[LogSource]:
    channel = str(event.get("Channel"))
    event_id = _as_int(event.get("EventID"))
    sources = {LogSource(product="windows")}
    if channel == SYSMON_CHANNEL:
        sources.add(LogSource(product="windows", service="sysmon"))
        if event_id in SYSMON_CATEGORIES:
            sources.add(LogSource(product="windows", category=SYSMON_CATEGORIES[event_id]))
    elif channel == SECURITY_CHANNEL:
        sources.add(LogSource(product="windows", service="security"))
    elif channel == POWERSHELL_CHANNEL:
        sources.add(LogSource(product="windows", service="powershell"))
        if event_id in POWERSHELL_CATEGORIES:
            sources.add(LogSource(product="windows", category=POWERSHELL_CATEGORIES[event_id]))
    return frozenset(sources)


def _classify_linux(event: Event) -> frozenset[LogSource]:
    sources = {LogSource(product="linux"), LogSource(product="linux", service="auditd")}
    if event.get("type") == "EXECVE":
        sources.add(LogSource(product="linux", category="process_creation"))
    return frozenset(sources)


def normalize(event: Event) -> Event:
    """Add derived Sigma-style fields without touching the originals.

    * auditd ``EXECVE`` - derives ``CommandLine`` (``a0 .. aN`` joined) and ``Image``
      (``exe`` when the collector merged the ``SYSCALL`` record, else ``a0``).
    * Windows ``EventID`` - coerced to ``int`` when the collector shipped it as a string.
    """
    if plane_of(event) is Plane.LINUX and event.get("type") == "EXECVE":
        args = [str(event[k]) for k in sorted(_arg_keys(event), key=lambda k: int(k[1:]))]
        enriched = dict(event)
        enriched.setdefault("CommandLine", " ".join(args))
        enriched.setdefault("Image", event.get("exe") or (args[0] if args else ""))
        return enriched
    if plane_of(event) is Plane.WINDOWS and isinstance(event.get("EventID"), str):
        enriched = dict(event)
        enriched["EventID"] = _as_int(event["EventID"])
        return enriched
    return event


def _arg_keys(event: Event) -> list[str]:
    return [k for k in event if len(k) > 1 and k[0] == "a" and k[1:].isdigit()]


def _as_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
