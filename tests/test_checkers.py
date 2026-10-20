"""Reference vs. spec checker on the cases the site uses as presets.

Every spec-checker witness is replayed through the reference enforcer: an
"expansion" verdict is only trusted if old denies and new allows the witness.
"""

import pytest

from app import reference, spec_checker
from app.policy_format import normalize


def pol(tool, **conds):
    return normalize({tool: [{"effect": "allow", "conditions": conds}]})


S = {"type": "string"}

CASES = [
    # id, old, new, expected spec verdict, expected reference verdict
    ("anchored_to_wildcard",
     pol("send_email", to={"type": "string", "pattern": r"^alice@x\.com$"}),
     pol("send_email", to={"type": "string", "pattern": ".*"}),
     "expansion", "narrowing"),
    ("enum_to_unanchored_pattern",
     pol("send_email", to={"type": "string", "enum": ["alice@x.com"]}),
     pol("send_email", to={"type": "string", "pattern": r"alice@x\.com"}),
     "expansion", "narrowing"),
    ("word_boundary_to_unrestricted",
     pol("get_webpage", url={"type": "string", "pattern": r"\bexample\.com\b"}),
     pol("get_webpage", url=S),
     "expansion", "narrowing"),
    ("enum_widened",
     pol("send_email", to={"type": "string", "enum": ["alice@x.com"]}),
     pol("send_email", to={"type": "string", "enum": ["alice@x.com", "eve@evil.com"]}),
     "expansion", "expansion"),
    ("restriction_dropped",
     pol("send_email", to={"type": "string", "enum": ["alice@x.com"]}),
     normalize({"send_email": [{"effect": "allow", "conditions": {}}]}),
     "expansion", "expansion"),
    ("paper_P2_to_P3_narrowing",
     pol("send_slack_msg", to=S, body=S),
     pol("send_slack_msg", to={"type": "string", "enum": ["alice"]}, body=S),
     "narrowing", "narrowing"),
    ("anchored_pattern_to_enum",
     pol("send_email", to={"type": "string", "pattern": r"^[a-z]+@x\.com$"}),
     pol("send_email", to={"type": "string", "enum": ["alice@x.com"]}),
     "narrowing", "narrowing"),
    ("amount_cap_raised",
     pol("send_money", amount={"type": "number", "maximum": 100}),
     pol("send_money", amount={"type": "number", "maximum": 1000}),
     "expansion", "expansion"),
    ("dollar_allows_trailing_newline",
     pol("send_email", to={"type": "string", "enum": ["alice@x.com"]}),
     pol("send_email", to={"type": "string", "pattern": r"^alice@x\.com$"}),
     "expansion", "narrowing"),
]


@pytest.mark.parametrize("cid,old,new,spec_exp,ref_exp", CASES, ids=[c[0] for c in CASES])
def test_verdicts(cid, old, new, spec_exp, ref_exp):
    spec = spec_checker.compare(old, new)
    assert spec["verdict"] == spec_exp, spec
    ref = reference.is_narrowing(old, new)
    assert ("narrowing" if ref["narrowing"] else "expansion") == ref_exp, ref

    for t in spec["tools"]:
        if t.get("basis") == "witness":
            tool, w = t["tool"], t["witness"]
            assert not reference.check_call(old, tool, w)["allowed"], (cid, w)
            assert reference.check_call(new, tool, w)["allowed"], (cid, w)


def test_forbid_rule_and_second_allow_rule():
    # Two allow rules: the reference enforcer stops at the first failing
    # priority-100 allow rule; Algorithm 2 keeps going.
    p = normalize({"send_email": [
        {"effect": "allow", "conditions": {"to": {"type": "string", "enum": ["alice@x.com"]}}},
        {"effect": "allow", "conditions": {"to": {"type": "string", "enum": ["bob@x.com"]}}},
    ]})
    assert spec_checker.evaluate_call(p, "send_email", {"to": "bob@x.com"})["allowed"]
    assert not reference.check_call(p, "send_email", {"to": "bob@x.com"})["allowed"]

    f = normalize({"send_email": [
        {"effect": "forbid", "conditions": {"to": {"type": "string", "pattern": r"@evil\.com$"}}},
        {"effect": "allow", "conditions": {}},
    ]})
    assert not spec_checker.evaluate_call(f, "send_email", {"to": "eve@evil.com"})["allowed"]
    assert spec_checker.evaluate_call(f, "send_email", {"to": "alice@x.com"})["allowed"]


def test_unsupported_fails_closed():
    old = pol("t", x={"type": "string", "pattern": r"(?<=a)b"})
    new = pol("t", x=S)
    r = spec_checker.compare(old, new)
    assert r["verdict"] == "expansion" and r["tools"][0]["basis"] == "unsupported"


def test_format_is_a_noop_warning():
    old = pol("send_email", to={"type": "string", "enum": ["alice@x.com"]})
    new = pol("send_email", to={"type": "string", "format": "email"})
    r = spec_checker.compare(old, new)
    assert r["verdict"] == "expansion"
    assert any("format" in w for w in r["tools"][0]["warnings"])
