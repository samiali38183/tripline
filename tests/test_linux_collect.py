"""Linux collector tests: raw audit.log parsing, marker slicing, fixture writing, rule firing."""

from __future__ import annotations

from pathlib import Path

from tripline.engine.rules import evaluate, load_rules
from tripline.linux.collect import collect, command_line, marker_of, parse_records, slice_by_markers
from tripline.logsource import classify, normalize
from tripline.scenarios import load_scenarios

RUN = "11111111-aaaa-4bbb-8ccc-000000000001"
T_SETUID = "759055b3-3885-4582-a8ec-c00c9d64dd79"
T_CRON = "078e69eb-d9fb-450e-b9d0-2e118217c846"


def _hex(s: str) -> str:
    return s.encode().hex().upper()


def _execve(
    serial: int, ts: float, argv: list[str], exe: str, key: str = "tripline_exec"
) -> list[str]:
    args = " ".join(
        f"a{i}={_hex(a)}" if (" " in a or '"' in a) else f'a{i}="{a}"' for i, a in enumerate(argv)
    )
    proctitle = _hex("\x00".join(argv))
    return [
        f"type=SYSCALL msg=audit({ts:.3f}:{serial}): arch=c000003e syscall=59 success=yes exit=0 "
        f'ppid=100 pid={serial} auid=1001 uid=0 comm="{Path(exe).name}" exe="{exe}" key="{key}"',
        f"type=EXECVE msg=audit({ts:.3f}:{serial}): argc={len(argv)} {args}",
        f'type=CWD msg=audit({ts:.3f}:{serial}): cwd="/home/runner"',
        f'type=PATH msg=audit({ts:.3f}:{serial}): item=0 name="{exe}" inode=1 nametype=NORMAL',
        f"type=PROCTITLE msg=audit({ts:.3f}:{serial}): proctitle={proctitle}",
    ]


def _file_create(serial: int, ts: float, name: str) -> list[str]:
    return [
        f"type=SYSCALL msg=audit({ts:.3f}:{serial}): arch=c000003e syscall=257 success=yes exit=3 "
        f'uid=0 comm="sh" exe="/usr/bin/dash" key="tripline_cron"',
        f'type=CWD msg=audit({ts:.3f}:{serial}): cwd="/home/runner"',
        f'type=PATH msg=audit({ts:.3f}:{serial}): item=0 name="/etc/cron.d/" inode=2 nametype=PARENT',
        f'type=PATH msg=audit({ts:.3f}:{serial}): item=1 name="{name}" inode=3 nametype=CREATE',
    ]


def _marker(serial: int, ts: float, test: str, phase: str) -> list[str]:
    return _execve(
        serial, ts, ["sh", "-c", f"true tripline-marker {RUN} {test} {phase}"], "/usr/bin/dash"
    )


LOG = (
    _execve(1, 1700000000.0, ["node", "/runner/worker.js"], "/usr/bin/node")  # before any marker
    + _marker(2, 1700000001.0, T_SETUID, "start")
    + _execve(
        3,
        1700000002.0,
        [
            "sh",
            "-c",
            "sudo touch /tmp/evilBinary; sudo chown root /tmp/evilBinary; sudo chmod u+s /tmp/evilBinary",
        ],
        "/usr/bin/dash",
    )
    + _execve(4, 1700000002.5, ["chmod", "u+s", "/tmp/evilBinary"], "/usr/bin/chmod")
    + _marker(5, 1700000003.0, T_SETUID, "end")
    + _execve(6, 1700000003.5, ["node", "/runner/worker.js"], "/usr/bin/node")  # between tests
    + _marker(7, 1700000004.0, T_CRON, "start")
    + _execve(
        8,
        1700000005.0,
        ["sh", "-c", 'echo "* * * * * root /tmp/evil.sh" > /etc/cron.d/persistevil'],
        "/usr/bin/dash",
    )
    + _file_create(9, 1700000005.1, "/etc/cron.d/persistevil")
    + _marker(10, 1700000006.0, T_CRON, "end")
)


def test_parse_merges_records_and_decodes_hex():
    events = parse_records(LOG)
    assert len(events) == 10
    e = events[2]
    assert e["type"] == "EXECVE" and e["exe"] == "/usr/bin/dash" and e["serial"] == "3"
    assert e["a2"].startswith("sudo touch") and "chmod u+s" in e["a2"]
    assert (
        e["proctitle"]
        == "sh -c sudo touch /tmp/evilBinary; sudo chown root /tmp/evilBinary; sudo chmod u+s /tmp/evilBinary"
    )
    assert e["timestamp"] == "2023-11-14T22:13:22.000Z"
    assert e["record_types"] == ["CWD", "EXECVE", "PATH", "PROCTITLE", "SYSCALL"]
    assert command_line(e) == e["proctitle"]
    created = events[8]
    assert created["type"] == "SYSCALL" and created["TargetFilename"] == "/etc/cron.d/persistevil"


def test_long_argument_chunks_are_joined():
    lines = [
        'type=EXECVE msg=audit(1700000000.000:50): argc=2 a0="sh" a1[0]="abc" a1[1]="def"',
    ]
    (event,) = parse_records(lines)
    assert event["a1"] == "abcdef" and command_line(event) == "sh abcdef"


def test_markers_and_slicing():
    events = parse_records(LOG)
    assert marker_of(events[1]).test_guid == T_SETUID and marker_of(events[1]).phase == "start"
    assert marker_of(events[0]) is None
    buckets = slice_by_markers(events)
    assert set(buckets) == {T_SETUID, T_CRON}
    assert [e["serial"] for e in buckets[T_SETUID]] == ["3", "4"]
    assert [e["serial"] for e in buckets[T_CRON]] == ["8", "9"]
    assert buckets[T_CRON][0]["tripline"] == {"run_guid": RUN, "atomic_test": T_CRON}


def test_normalized_events_fire_the_linux_rules(repo_root):
    rules = load_rules(repo_root / "rules" / "sigma")
    by_id = {r.id: r for r in rules.rules}
    events = parse_records(LOG)
    setuid_sh = events[2]
    assert "product=linux category=process_creation" in {str(s) for s in classify(setuid_sh)}
    assert normalize(setuid_sh)["CommandLine"].startswith("sh -c sudo touch")
    assert evaluate(by_id["c21c4eaa-ba2e-419a-92b2-8371703cbe21"], setuid_sh) is True
    cron_create = events[8]
    assert "product=linux category=file_event" in {str(s) for s in classify(cron_create)}
    assert evaluate(by_id["6c4e2f43-d94d-4ead-b64d-97e53fa2bd05"], cron_create) is True
    assert (
        evaluate(by_id["6c4e2f43-d94d-4ead-b64d-97e53fa2bd05"], setuid_sh) is None
    )  # not a file_event


def test_collect_writes_fixtures_for_seen_scenarios(repo_root, tmp_path):
    scenarios = load_scenarios(repo_root / "scenarios")
    written = collect(
        LOG, scenarios, tmp_path, run_guid=RUN, source="https://example.invalid/run/1"
    )
    assert set(written) == {"t1548-001-setuid-setgid", "t1053-003-cron-persistence"}
    import json

    manifest = json.loads((tmp_path / "t1053-003-cron-persistence" / "manifest.json").read_text())
    assert manifest["events"] == 2 and manifest["created_files"] == ["/etc/cron.d/persistevil"]
    assert manifest["atomic_tests"][T_CRON] == 2 and manifest["run_guid"] == RUN
    text = (tmp_path / "t1548-001-setuid-setgid" / "run.ndjson").read_bytes()
    assert text.count(b"\n") == 2 and b"\r\n" not in text
