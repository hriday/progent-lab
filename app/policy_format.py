"""Policy representations and conversions.

The site uses the paper's Figure 9 format, which is what a person edits:

    {
      "send_email": [
        {"effect": "allow", "priority": 100,
         "conditions": {"to": {"type": "string", "enum": ["alice@x.com"]}}}
      ]
    }

The reference implementation stores the same thing as tuples
``(priority, effect, conditions, fallback)`` with effect 0=allow, 1=forbid and
fallback 0=return message. The LLM prompts in the reference code speak a third
form, ``[{"name": tool, "args": conditions}]``, which always means
"priority-100 allow rule".
"""

from __future__ import annotations

from typing import Any

Policy = dict[str, list[dict[str, Any]]]
RefPolicy = dict[str, list[tuple]]

GENERATED_PRIORITY = 100  # the reference code treats only priority-100 rules as LLM-generated


class PolicyFormatError(ValueError):
    pass


def normalize(policy: Any) -> Policy:
    """Validate a Figure-9 policy and fill defaults."""
    if not isinstance(policy, dict):
        raise PolicyFormatError("A policy must be a JSON object mapping tool names to lists of rules.")
    out: Policy = {}
    for tool, rules in policy.items():
        if not isinstance(tool, str) or not tool:
            raise PolicyFormatError("Tool names must be non-empty strings.")
        if not isinstance(rules, list):
            raise PolicyFormatError(f"Rules for '{tool}' must be a list.")
        norm_rules = []
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise PolicyFormatError(f"Rule {i} for '{tool}' must be an object.")
            effect = rule.get("effect", "allow")
            if effect not in ("allow", "forbid"):
                raise PolicyFormatError(f"Rule {i} for '{tool}': effect must be 'allow' or 'forbid'.")
            priority = rule.get("priority", GENERATED_PRIORITY)
            if not isinstance(priority, int) or isinstance(priority, bool):
                raise PolicyFormatError(f"Rule {i} for '{tool}': priority must be an integer.")
            conditions = rule.get("conditions", {})
            if not isinstance(conditions, dict):
                raise PolicyFormatError(f"Rule {i} for '{tool}': conditions must map argument names to JSON Schemas.")
            for arg, schema in conditions.items():
                if not isinstance(schema, dict):
                    raise PolicyFormatError(
                        f"Rule {i} for '{tool}', argument '{arg}': each condition must be a JSON Schema object."
                    )
            norm_rules.append({"effect": effect, "priority": priority, "conditions": conditions})
        out[tool] = norm_rules
    return out


def to_reference(policy: Policy) -> RefPolicy:
    ref: RefPolicy = {}
    for tool, rules in policy.items():
        ref[tool] = [
            (r["priority"], 0 if r["effect"] == "allow" else 1, r["conditions"], 0) for r in rules
        ]
        # Same ordering the reference code's sort_policy() applies.
        ref[tool].sort(key=lambda x: (x[0], -x[1]))
    return ref


def from_generated(generated: list[dict[str, Any]]) -> Policy:
    """Convert the LLM's ``[{"name", "args"}]`` output into Figure-9 rules."""
    if not isinstance(generated, list):
        raise PolicyFormatError("The policy model must return a JSON array of {name, args} objects.")
    out: Policy = {}
    for item in generated:
        if not isinstance(item, dict) or "name" not in item:
            raise PolicyFormatError("Each generated entry needs a 'name'.")
        args = item.get("args") or {}
        if not isinstance(args, dict):
            raise PolicyFormatError(f"'args' for {item['name']} must be an object.")
        out.setdefault(item["name"], []).append(
            {"effect": "allow", "priority": GENERATED_PRIORITY, "conditions": args}
        )
    return out


def generated_part(policy: Policy) -> list[dict[str, Any]]:
    """The ``CURRENT_RESTRICTIONS`` the update prompt expects: priority-100 allow rules only."""
    out = []
    for tool, rules in policy.items():
        for r in rules:
            if r["priority"] == GENERATED_PRIORITY and r["effect"] == "allow":
                out.append({"name": tool, "args": r["conditions"]})
    return out


def merge(generic: Policy, task: Policy) -> Policy:
    """Generic (human) rules plus the task-specific (generated) rules for the same tool."""
    out: Policy = {t: list(rs) for t, rs in generic.items()}
    for tool, rules in task.items():
        out.setdefault(tool, []).extend(rules)
    return out


def replace_generated(policy: Policy, new_task: Policy) -> Policy:
    """Mirror the reference update: drop all priority-100 rules, then add the new ones."""
    kept: Policy = {}
    for tool, rules in policy.items():
        rest = [r for r in rules if r["priority"] != GENERATED_PRIORITY]
        if rest:
            kept[tool] = rest
    return merge(kept, new_task)
