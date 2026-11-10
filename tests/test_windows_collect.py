"""Windows collector tests: marker slicing across channels, fixture writing, rule firing."""

from __future__ import annotations

import json

from tripline.engine.rules import evaluate, load_rules
from tripline.logsource import classify
from tripline.scenarios import load_scenarios
from tripline.windows.collect import collect, marker_of, slice_by_markers

RUN = "22222222-aaaa-4bbb-8ccc-000000000002"
T_ENC = "0d181431-ddf3-4826-8055-2dbf63ae848b"  # T1059.001 -EncodedCommand
T_WMIC = "b3bdfc91-b33e-4c6d-a5c8-d64bee0276b3"  # T1047 wmic process call create
SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS = "Microsoft-Windows-PowerShell/Operational"


def _ts(seconds: int) -> str:
    return f"2026-11-04T14:00:{seconds:02d}.0000000Z"


def _sysmon1(
    rec: int, seconds: int, image: str, cmd: str, parent: str = "C:\\Windows\\System32\\cmd.exe"
):
    return {
        "Channel": SYSMON,
        "EventID": 1,
        "TimeCreated": _ts(seconds),
        "ProviderName": "Microsoft-Windows-Sysmon",
        "Computer": "runner",
        "RecordNumber": rec,
        "Image": image,
        "CommandLine": cmd,
        "ParentImage": parent,
        "OriginalFileName": image.rsplit("\\", 1)[-1],
        "User": "runner\\runneradmin",
    }


def _sec4688(rec: int, seconds: int, image: str, cmd: str):
    return {
        "Channel": "Security",
        "EventID": 4688,
        "TimeCreated": _ts(seconds),
        "RecordNumber": rec,
        "NewProcessName": image,
        "CommandLine": cmd,
    }


def _ps4104(rec: int, seconds: int, text: str):
    return {
        "Channel": PS,
        "EventID": 4104,
        "TimeCreated": _ts(seconds),
        "RecordNumber": rec,
        "ScriptBlockText": text,
    }


def _marker(rec: int, seconds: int, test: str, phase: str, channel: str = SYSMON, run: str = RUN):
    cmd = f'cmd.exe /c "echo tripline-marker {run} {test} {phase}"'
    if channel == SYSMON:
        return _sysmon1(
            rec,
            seconds,
            "C:\\Windows\\System32\\cmd.exe",
            cmd,
            parent="C:\\Program Files\\PowerShell\\7\\pwsh.exe",
        )
    return _sec4688(rec, seconds, "C:\\Windows\\System32\\cmd.exe", cmd)


ENCODED = "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACIA"
EVENTS = [
    _ps4104(
        900,
        1,
        f"Invoke-AtomicTest T1059.001 -TestGuids {T_ENC}  # the loop mentions tripline-marker, not a boundary",
    ),
    _marker(1, 2, T_ENC, "start"),
    _marker(500, 2, T_ENC, "start", channel="Security"),  # same marker seen by Security
    _sysmon1(2, 3, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ENCODED),
    _sec4688(501, 3, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", ENCODED),
    _ps4104(901, 4, 'Write-Host "Hello"'),
    _marker(3, 5, T_ENC, "end"),
    _marker(502, 5, T_ENC, "end", channel="Security"),
    _sysmon1(
        4, 6, "C:\\Windows\\System32\\conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0x4"
    ),  # between tests
    _marker(5, 7, T_WMIC, "start"),
    _sysmon1(6, 8, "C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic process call create notepad.exe"),
    _sysmon1(
        7,
        9,
        "C:\\Windows\\System32\\notepad.exe",
        "notepad.exe",
        parent="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    ),
    _marker(8, 10, T_WMIC, "end"),
]


def test_marker_detection_only_on_process_creation():
    assert marker_of(EVENTS[1]).test_guid == T_ENC and marker_of(EVENTS[1]).phase == "start"
    assert marker_of(EVENTS[2]).phase == "start"  # Security 4688 copy
    assert marker_of(EVENTS[0]) is None  # 4104 mentioning the marker string
    assert marker_of(EVENTS[3]) is None


def test_slicing_orders_by_time_across_channels():
    shuffled = list(reversed(EVENTS))
    buckets = slice_by_markers(shuffled, run_guid=RUN)
    assert set(buckets) == {T_ENC, T_WMIC}
    assert [e["RecordNumber"] for e in buckets[T_ENC]] == [2, 501, 901]
    assert [e["RecordNumber"] for e in buckets[T_WMIC]] == [6, 7]
    assert all(e["tripline"] == {"run_guid": RUN, "atomic_test": T_ENC} for e in buckets[T_ENC])


def test_fixture_events_fire_expected_rules(repo_root):
    rules = load_rules(repo_root / "rules" / "sigma")
    by_id = {r.id: r for r in rules.rules}
    enc = EVENTS[3]
    assert "product=windows category=process_creation" in {str(s) for s in classify(enc)}
    assert evaluate(by_id["fb843269-508c-4b76-8b8d-88679db22ce7"], enc) is True
    wmic = EVENTS[10]
    assert evaluate(by_id["526be59f-a573-4eea-b5f7-f0973207634d"], wmic) is True
    assert evaluate(by_id["526be59f-a573-4eea-b5f7-f0973207634d"], enc) is False
    sec = EVENTS[4]  # Security 4688 is not process_creation for Sysmon-shaped rules
    assert evaluate(by_id["fb843269-508c-4b76-8b8d-88679db22ce7"], sec) is None


def test_collect_writes_fixtures_and_manifest(repo_root, tmp_path):
    scenarios = load_scenarios(repo_root / "scenarios")
    written = collect(
        EVENTS, scenarios, tmp_path, run_guid=RUN, source="https://example.invalid/run/2"
    )
    assert set(written) == {
        "t1059-001-powershell-encoded-download",
        "t1047-wmic-process-call-create",
    }
    manifest = json.loads(
        (tmp_path / "t1047-wmic-process-call-create" / "manifest.json").read_text()
    )
    assert manifest["events"] == 2 and manifest["atomic_tests"][T_WMIC] == 2
    assert manifest["events_by_channel_and_id"] == {f"{SYSMON}:1": 2}
    enc_manifest = json.loads(
        (tmp_path / "t1059-001-powershell-encoded-download" / "manifest.json").read_text()
    )
    assert enc_manifest["events_by_channel_and_id"] == {
        f"{SYSMON}:1": 1,
        f"{PS}:4104": 1,
        "Security:4688": 1,
    }
    raw = (tmp_path / "t1047-wmic-process-call-create" / "run.ndjson").read_bytes()
    assert raw.count(b"\n") == 2 and b"\r\n" not in raw


OTHER_RUN = "88888888-aaaa-4bbb-8ccc-000000000008"


def _proc(rec: int, seconds: int, name: str):
    return _sysmon1(rec, seconds, rf"C:\Windows\System32\{name}.exe", name)


def test_slice_ignores_markers_of_another_run():
    events = [
        _marker(1, 1, T_ENC, "start"),
        _proc(2, 2, "whoami"),
        _marker(3, 3, T_WMIC, "start", run=OTHER_RUN),
        _proc(4, 4, "hostname"),
        _marker(5, 5, T_ENC, "end"),
    ]
    buckets = slice_by_markers(events, run_guid=RUN)
    assert set(buckets) == {T_ENC}
    assert [e["RecordNumber"] for e in buckets[T_ENC]] == [2, 4]


def test_slice_two_sequential_runs_in_one_export():
    """Run 1 never closed its window; run 2's slice must not contain run 1's events."""
    events = [
        _marker(1, 1, T_ENC, "start", run=OTHER_RUN),
        _proc(2, 2, "stale"),
        _marker(3, 3, T_ENC, "start"),
        _proc(4, 4, "whoami"),
        _marker(5, 5, T_ENC, "end"),
        _marker(6, 6, T_WMIC, "start", run=OTHER_RUN),
        _proc(7, 7, "stale-too"),
        _marker(8, 8, T_WMIC, "end", run=OTHER_RUN),
    ]
    mine = slice_by_markers(list(reversed(events)), run_guid=RUN)
    assert {g: [e["RecordNumber"] for e in v] for g, v in mine.items()} == {T_ENC: [4]}
    theirs = slice_by_markers(events, run_guid=OTHER_RUN)
    assert [e["RecordNumber"] for e in theirs[T_ENC]] == [2, 4]
    assert all(e["tripline"]["run_guid"] == OTHER_RUN for e in theirs[T_ENC])


def test_collect_only_writes_events_of_the_requested_run(repo_root, tmp_path):
    scenarios = load_scenarios(repo_root / "scenarios")
    events = [
        _marker(1, 1, T_ENC, "start", run=OTHER_RUN),
        _proc(2, 2, "stale"),
        _marker(3, 3, T_WMIC, "start"),
        _proc(4, 4, "whoami"),
        _marker(5, 5, T_WMIC, "end"),
    ]
    written = collect(events, scenarios, tmp_path, run_guid=RUN, source="x")
    assert set(written) == {"t1047-wmic-process-call-create"}
    assert b"stale" not in written["t1047-wmic-process-call-create"].read_bytes()
