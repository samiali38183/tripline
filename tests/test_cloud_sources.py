"""Cloud fixture recipes: build from local sources without network, manifest shape."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tripline.cloud import sources
from tripline.cloud.sources import RECIPES, Recipe, Source, build_fixture
from tripline.events import read_ndjson

STOP = {
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "eventTime": "2024-07-31T13:06:24Z",
    "userAgent": "aws-cli/2.0",
    "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/x"},
}


def test_recipes_cover_the_four_cloud_scenarios():
    assert [r.scenario_id for r in RECIPES] == [
        "t1078-004-console-login-without-mfa",
        "t1530-s3-bucket-exposure",
        "t1562-008-cloudtrail-stop",
        "t1098-001-iam-backdoor-access-key",
    ]
    for recipe in RECIPES:
        assert recipe.sources and recipe.description
        for source in recipe.sources:
            assert source.url.startswith("https://") and source.license


def test_source_fetch_uses_cache(tmp_path, monkeypatch):
    src = Source(name="s", url="https://example.invalid/x.json", license="x", filename="x.json")
    (tmp_path / "x.json").write_text("[]", encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(sources.urllib.request, "urlopen", lambda *a, **k: calls.append("net"))
    assert src.fetch(tmp_path) == tmp_path / "x.json"
    assert calls == []


def test_build_fixture_writes_ndjson_and_manifest(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "stop.json").write_text(
        json.dumps([STOP, {**STOP, "eventTime": "2024-07-31T13:07:24Z"}])
    )
    src = Source(
        name="stratus:stop",
        url="https://example.invalid/stop.json",
        license="Apache-2.0",
        filename="stop.json",
    )
    recipe = Recipe(
        scenario_id="t1562-008-test",
        sources=(src,),
        load=lambda paths: sources.load_stratus_log(paths[src.name]),
        description="test",
    )
    base = datetime(2026, 1, 1, tzinfo=UTC)
    out = build_fixture(recipe, cache, tmp_path / "fixtures", base_time=base)
    events = read_ndjson(out)
    manifest = json.loads((out.parent / "manifest.json").read_text(encoding="utf-8"))
    assert out == tmp_path / "fixtures" / "t1562-008-test" / "run.ndjson"
    assert [e["eventTime"] for e in events] == ["2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z"]
    assert manifest["events"] == 2 and manifest["event_names"] == ["StopLogging"]
    assert manifest["original_time_window"] == ["2024-07-31T13:06:24Z", "2024-07-31T13:07:24Z"]
    assert manifest["sources"][0]["license"] == "Apache-2.0"
    assert all(e["userAgent"].endswith(f"tripline/{manifest['run_guid']}") for e in events)


def test_build_fixture_rejects_empty_selection(tmp_path):
    src = Source(name="e", url="https://example.invalid/e.json", license="x", filename="e.json")
    (tmp_path / "e.json").write_text("[]", encoding="utf-8")
    recipe = Recipe(scenario_id="x", sources=(src,), load=lambda paths: [], description="d")
    with pytest.raises(ValueError, match="selected no records"):
        build_fixture(recipe, tmp_path, tmp_path / "fx")


def test_selection_predicates_match_real_shapes():
    acl = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketAcl",
        "requestParameters": {
            "AccessControlPolicy": {
                "AccessControlList": {
                    "Grant": [
                        {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}
                    ]
                }
            }
        },
    }
    policy = {
        "eventSource": "s3.amazonaws.com",
        "eventName": "PutBucketPolicy",
        "requestParameters": {"bucketPolicy": {"Statement": [{"Principal": "*"}]}},
    }
    assert sources._is_public_s3_grant(acl) and sources._is_public_s3_grant(policy)
    assert not sources._is_public_s3_grant({**acl, "errorCode": "AccessDenied"})
    assert not sources._is_public_s3_grant(
        {"eventSource": "s3.amazonaws.com", "eventName": "GetObject"}
    )
    listing = {"eventName": "ListBuckets", "userIdentity": {"userName": "backup"}}
    assert sources._is_backup_user_listing(listing)
    assert not sources._is_backup_user_listing({**listing, "errorCode": "x"})
    login = {"eventName": "ConsoleLogin", "additionalEventData": {"MFAUsed": "No"}}
    assert sources._is_console_login(login) and not sources._is_console_login(
        {"eventName": "ConsoleLogin"}
    )


def test_load_functions_use_recipe_sources(tmp_path):
    """Each recipe loader must only ask for paths of the sources it declares."""
    for recipe in RECIPES:
        with pytest.raises(KeyError):
            recipe.load({})
    assert isinstance(Path(sources.FLAWS.filename), Path)
