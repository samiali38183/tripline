"""Recipes that turn public CloudTrail datasets into the committed cloud fixtures.

Every recipe names its upstream source and licence, and selects records with a plain
predicate so you can see exactly which real events were kept. ``tripline cloud build``
downloads the sources into a cache directory, applies the recipes, replays the records
(timestamp rebase + run GUID) and writes ``fixtures/cloud/<scenario>/run.ndjson`` next to a
``manifest.json`` describing where each event came from.
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from tripline.cloud.replay import (
    RecordFilter,
    iter_flaws_records,
    load_stratus_log,
    new_run_guid,
    replay_records,
    select,
    select_many,
    time_window,
)
from tripline.events import get_field, write_ndjson, write_text_lf
from tripline.models import Event

STRATUS_RAW = (
    "https://raw.githubusercontent.com/DataDog/stratus-red-team/main/docs/detonation-logs/"
)
STRATUS_LICENSE = "Apache-2.0 (https://github.com/DataDog/stratus-red-team/blob/main/LICENSE)"
FLAWS_URL = "https://summitroute.com/downloads/flaws_cloudtrail_logs.tar"
FLAWS_LICENSE = (
    "Published by Scott Piper / Summit Route for public analysis "
    "(https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/)"
)


@dataclass(frozen=True, slots=True)
class Source:
    """A downloadable upstream dataset."""

    name: str
    url: str
    license: str
    filename: str

    def fetch(self, cache_dir: Path) -> Path:
        """Download into ``cache_dir`` unless already present; return the local path."""
        cache_dir.mkdir(parents=True, exist_ok=True)
        target = cache_dir / self.filename
        if not target.exists():
            with urllib.request.urlopen(self.url, timeout=120) as response:
                target.write_bytes(response.read())
        return target


@dataclass(frozen=True, slots=True)
class Recipe:
    """How one scenario's fixture is carved out of its sources."""

    scenario_id: str
    sources: tuple[Source, ...]
    load: Callable[[dict[str, Path]], list[Event]]
    description: str


def _stratus(technique: str) -> Source:
    return Source(
        name=f"stratus:{technique}",
        url=f"{STRATUS_RAW}{technique}.json",
        license=STRATUS_LICENSE,
        filename=f"{technique}.json",
    )


FLAWS = Source(
    name="flaws.cloud", url=FLAWS_URL, license=FLAWS_LICENSE, filename="flaws_cloudtrail_logs.tar"
)
STRATUS_CONSOLE_LOGIN = _stratus("aws.initial-access.console-login-without-mfa")
STRATUS_CLOUDTRAIL_STOP = _stratus("aws.defense-evasion.cloudtrail-stop")
STRATUS_IAM_BACKDOOR = _stratus("aws.persistence.iam-backdoor-user")


def _is_console_login(record: Event) -> bool:
    return record.get("eventName") == "ConsoleLogin" and bool(record.get("additionalEventData"))


def _is_public_s3_grant(record: Event) -> bool:
    if record.get("eventSource") != "s3.amazonaws.com" or record.get("errorCode"):
        return False
    if record.get("eventName") == "PutBucketAcl":
        uris = get_field(
            record, "requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI"
        )
        return any("AllUsers" in str(u) for u in (uris or []))
    if record.get("eventName") == "PutBucketPolicy":
        principals = get_field(record, "requestParameters.bucketPolicy.Statement.Principal")
        return any(
            p == "*" or (isinstance(p, dict) and p.get("AWS") == "*") for p in principals or []
        )
    return False


def _is_backup_user_listing(record: Event) -> bool:
    return (
        record.get("eventName") == "ListBuckets"
        and get_field(record, "userIdentity.userName") == "backup"
        and not record.get("errorCode")
    )


def _load_console_login(paths: dict[str, Path]) -> list[Event]:
    stratus = load_stratus_log(paths[STRATUS_CONSOLE_LOGIN.name])
    flaws = iter_flaws_records(paths[FLAWS.name])
    logins = select(
        flaws,
        lambda r: _is_console_login(r) and get_field(r, "userIdentity.type") in {"IAMUser", "Root"},
        limit=6,
    )
    return stratus + logins


def _load_s3_exposure(paths: dict[str, Path]) -> list[Event]:
    quotas: dict[str, tuple[RecordFilter, int]] = {
        "grants": (_is_public_s3_grant, 6),
        "listings": (_is_backup_user_listing, 4),
    }
    chosen = select_many(iter_flaws_records(paths[FLAWS.name]), quotas)
    return chosen["grants"] + chosen["listings"]


def _load_stratus_only(source: Source) -> Callable[[dict[str, Path]], list[Event]]:
    def load(paths: dict[str, Path]) -> list[Event]:
        return load_stratus_log(paths[source.name])

    return load


RECIPES: tuple[Recipe, ...] = (
    Recipe(
        scenario_id="t1078-004-console-login-without-mfa",
        sources=(STRATUS_CONSOLE_LOGIN, FLAWS),
        load=_load_console_login,
        description=(
            "Stratus console-login-without-mfa detonation plus the first IAM-user and root "
            "ConsoleLogin records from flaws.cloud."
        ),
    ),
    Recipe(
        scenario_id="t1530-s3-bucket-exposure",
        sources=(FLAWS,),
        load=_load_s3_exposure,
        description=(
            "flaws.cloud PutBucketAcl/PutBucketPolicy calls that granted AllUsers or Principal '*' "
            "on level buckets, plus ListBuckets calls by the leaked 'backup' IAM user."
        ),
    ),
    Recipe(
        scenario_id="t1562-008-cloudtrail-stop",
        sources=(STRATUS_CLOUDTRAIL_STOP,),
        load=_load_stratus_only(STRATUS_CLOUDTRAIL_STOP),
        description="Stratus aws.defense-evasion.cloudtrail-stop detonation (StopLogging).",
    ),
    Recipe(
        scenario_id="t1098-001-iam-backdoor-access-key",
        sources=(STRATUS_IAM_BACKDOOR,),
        load=_load_stratus_only(STRATUS_IAM_BACKDOOR),
        description=(
            "Stratus aws.persistence.iam-backdoor-user detonation "
            "(CreateAccessKey for another user)."
        ),
    ),
)


def build_fixture(
    recipe: Recipe, cache_dir: Path, fixtures_dir: Path, *, base_time: datetime | None = None
) -> Path:
    """Download sources, apply the recipe, replay, and write ``run.ndjson`` + ``manifest.json``."""
    paths = {source.name: source.fetch(cache_dir) for source in recipe.sources}
    records = recipe.load(paths)
    if not records:
        raise ValueError(f"{recipe.scenario_id}: recipe selected no records")
    run_guid = new_run_guid()
    base = base_time or datetime.now(UTC)
    replayed = replay_records(records, run_guid=run_guid, base_time=base)
    out_dir = fixtures_dir / recipe.scenario_id
    target = out_dir / "run.ndjson"
    write_ndjson(target, replayed)
    manifest = {
        "scenario_id": recipe.scenario_id,
        "run_guid": run_guid,
        "description": recipe.description,
        "events": len(replayed),
        "original_time_window": time_window(records),
        "replayed_time_window": time_window(replayed),
        "event_names": sorted({str(r.get("eventName")) for r in replayed}),
        "sources": [{"name": s.name, "url": s.url, "license": s.license} for s in recipe.sources],
    }
    write_text_lf(out_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return target


def build_all(cache_dir: Path, fixtures_dir: Path) -> list[Path]:
    """Build every cloud fixture."""
    return [build_fixture(recipe, cache_dir, fixtures_dir) for recipe in RECIPES]
