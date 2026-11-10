"""Unit tests for the tripline Windows rules that close gaps documented in docs/findings.md F-003.

EVERY EVENT IN THIS FILE IS SYNTHETIC: hand-written to match the shape of Sysmon EID 1 and
Security 4698 records. None of it is recorded telemetry, none of it is committed under
``fixtures/``, and it does not count toward the scorecard. These tests prove the rule logic only;
whether the rules fire on a real runner is decided by the next recorded Windows run.
"""

from __future__ import annotations

import pytest

from tripline.engine.rules import evaluate, load_rules

SIGMAHQ_REDIRECT = "8e0bb260-d4b2-4fff-bb8d-3f82118e6892"
SIGMAHQ_TASK = "3a734d25-df5c-4b99-8034-af1ddb5883a4"
REDIRECT = "467585b7-9de8-40e5-bb2a-6626902ae295"
TASK = "eb3f5405-928e-441c-a867-0612f0f66dc9"
TEMP = r"C:\Users\runneradmin\AppData\Local\Temp" + "\\"
CMD = r"C:\Windows\System32\cmd.exe"


@pytest.fixture
def rules(repo_root):
    return {r.id: r for r in load_rules(repo_root / "rules" / "sigma").rules}


def _proc(cmd: str, cwd: str = TEMP, image: str = CMD) -> dict:
    """SYNTHETIC Sysmon EID 1."""
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "Image": image,
        "OriginalFileName": image.rsplit("\\", 1)[-1],
        "CommandLine": cmd,
        "CurrentDirectory": cwd,
    }


def _task(command: str, name: str = "\\spawn", args: str = "") -> dict:
    """SYNTHETIC Security 4698."""
    xml = (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        '<Actions Context="Author">'
        f"<Exec><Command>{command}</Command><Arguments>{args}</Arguments></Exec></Actions></Task>"
    )
    return {"Channel": "Security", "EventID": 4698, "TaskName": name, "TaskContent": xml}


# ------------------------------------------------------------------ T1059.003 relative redirect


@pytest.mark.parametrize(
    "cmd",
    [
        'cmd.exe /c "hostname > hello.txt"',
        r'C:\Windows\system32\cmd.exe /c "echo x>AtomicTest.vbs & cscript AtomicTest.vbs"',
        "cmd /c dir >> out.log",
        r'cmd /c "whoami > .\w.txt"',
        'cmd /c "dir > ""report.txt"""',
    ],
)
def test_relative_redirect_in_suspicious_cwd_fires(rules, cmd):
    assert evaluate(rules[REDIRECT], _proc(cmd)) is True, cmd


@pytest.mark.parametrize(
    ("cmd", "cwd"),
    [
        ('cmd.exe /c "hostname > hello.txt"', r"C:\Users\bob\Documents" + "\\"),  # benign cwd
        ('cmd.exe /c "hostname > hello.txt"', r"C:\Windows\System32" + "\\"),
        (r'cmd /c "dir > C:\Users\bob\x.txt"', TEMP),  # absolute: the SigmaHQ rule's territory
        (r"cmd /c dir > %TEMP%\x.txt", TEMP),
        ("cmd /c ping host 2>&1", TEMP),  # stream merge, not a file
        ("cmd /c dir", TEMP),
    ],
)
def test_redirect_rule_ignores_benign_shapes(rules, cmd, cwd):
    assert evaluate(rules[REDIRECT], _proc(cmd, cwd)) is False, (cmd, cwd)


def test_redirect_rule_needs_cmd_itself(rules):
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    event = _proc('powershell.exe -c "x > hello.txt"', image=ps)
    assert evaluate(rules[REDIRECT], event) is False


def test_the_sigmahq_rule_misses_what_the_tripline_rule_catches(rules):
    event = _proc('cmd.exe /c "hostname > hello.txt"')
    assert evaluate(rules[SIGMAHQ_REDIRECT], event) is False  # F-003 evasion
    assert evaluate(rules[REDIRECT], event) is True


# ------------------------------------------------------------------ T1053.005 task action


@pytest.mark.parametrize(
    "command",
    [
        r"C:\windows\system32\cmd.exe",
        r'"C:\Program Files\PowerShell\7\pwsh.exe"',
        r"%windir%\system32\wscript.exe",
        "mshta",
    ],
)
def test_task_with_interpreter_action_fires(rules, command):
    assert evaluate(rules[TASK], _task(command, args="/c calc.exe")) is True, command


@pytest.mark.parametrize(
    "event",
    [
        _task(r"C:\Program Files\Vendor\updater.exe"),  # not an interpreter
        _task(r"C:\windows\system32\cmd.exe", name=r"\Microsoft\Windows\Defrag\ScheduledDefrag"),
        {"Channel": "Security", "EventID": 4699, "TaskName": "\\x", "TaskContent": "cmd</Command>"},
    ],
)
def test_task_rule_ignores_benign_shapes(rules, event):
    assert evaluate(rules[TASK], event) is False


def test_the_sigmahq_task_rule_misses_a_system32_cmd_task(rules):
    event = _task(r"C:\windows\system32\cmd.exe", args="/c calc.exe")
    assert evaluate(rules[SIGMAHQ_TASK], event) is False  # F-003: needs a user-writable path
    assert evaluate(rules[TASK], event) is True
