"""A policy-containment checker that follows the paper's definitions.

Differences from the reference `security_policy_subset_check`, all deliberate:

* Patterns are modeled with the semantics the *enforcer* uses. `jsonschema`
  validates `pattern` with `re.search`, so an unanchored pattern matches any
  string that *contains* a match. The reference translator models full match.
* `^`, `$` and `\\Z` at the edges of a pattern (or of each top-level
  alternative) are supported; Python's `$` also matches before one trailing
  newline, and `.` does not match a newline, and both are modeled.
* Every rule counts. A tool's allowed set is the first-match result over its
  rules sorted by (priority, forbid-before-allow), i.e. Algorithm 2 /
  Equation 3, not only the first allow rule.
* Fail closed. Any construct that cannot be modeled exactly, and any solver
  "unknown", is reported and classified as an expansion.

Known approximation (reported as a warning, not hidden): `\\d`, `\\w`, `\\s`
are Unicode-aware in Python but modeled as their ASCII sets, so witnesses
that need non-ASCII digits/letters are not explored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

import jsonschema
import z3

try:  # Python 3.11+
    import re._constants as sre_c  # type: ignore[import-not-found]
    import re._parser as sre_parse  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    import sre_constants as sre_c  # type: ignore[no-redef]
    import sre_parse  # type: ignore[no-redef]

from .policy_format import Policy
from .reference import Z3_LOCK

SOLVER_TIMEOUT_MS = 8000
IGNORED_KEYWORDS = {"title", "description", "$comment", "default", "examples", "$schema", "$id"}

STR_RE = z3.ReSort(z3.StringSort())


class Unsupported(Exception):
    """A schema or regex construct that cannot be modeled exactly."""


@dataclass
class Ctx:
    warnings: list[str] = field(default_factory=list)

    def warn(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)


# --------------------------------------------------------------------------- regex


def _union(rs: list[z3.ReRef]) -> z3.ReRef:
    if not rs:
        return z3.Empty(STR_RE)
    return rs[0] if len(rs) == 1 else z3.Union(*rs)


def _concat(rs: list[z3.ReRef]) -> z3.ReRef:
    if not rs:
        return z3.Re(z3.StringVal(""))
    return rs[0] if len(rs) == 1 else z3.Concat(*rs)


def _allchar() -> z3.ReRef:
    return z3.AllChar(STR_RE)


def _not(r: z3.ReRef) -> z3.ReRef:
    """Any single character not in the single-character language r."""
    return z3.Intersect(_allchar(), z3.Complement(r))


def _lit(code: int) -> z3.ReRef:
    return z3.Re(z3.StringVal(chr(code)))


def _range(lo: int, hi: int) -> z3.ReRef:
    return z3.Range(chr(lo), chr(hi))


_ASCII_CATS = {
    "digit": lambda: _range(48, 57),
    "word": lambda: _union([_range(97, 122), _range(65, 90), _range(48, 57), _lit(95)]),
    "space": lambda: _union([_lit(c) for c in (32, 9, 10, 13, 12, 11)]),
}


def _category(cat: Any, ctx: Ctx) -> z3.ReRef:
    names = {
        sre_c.CATEGORY_DIGIT: ("digit", False),
        sre_c.CATEGORY_NOT_DIGIT: ("digit", True),
        sre_c.CATEGORY_WORD: ("word", False),
        sre_c.CATEGORY_NOT_WORD: ("word", True),
        sre_c.CATEGORY_SPACE: ("space", False),
        sre_c.CATEGORY_NOT_SPACE: ("space", True),
    }
    if cat not in names:
        raise Unsupported(f"regex category {cat}")
    name, neg = names[cat]
    ctx.warn("\\d, \\w and \\s are Unicode-aware in Python but modeled here as their ASCII sets.")
    base = _ASCII_CATS[name]()
    return _not(base) if neg else base


def _class(items: list, ctx: Ctx) -> z3.ReRef:
    negate = bool(items) and items[0][0] == sre_c.NEGATE
    if negate:
        items = items[1:]
    parts = []
    for op, av in items:
        if op == sre_c.LITERAL:
            parts.append(_lit(av))
        elif op == sre_c.RANGE:
            parts.append(_range(av[0], av[1]))
        elif op == sre_c.CATEGORY:
            parts.append(_category(av, ctx))
        else:
            raise Unsupported(f"regex class element {op}")
    u = _union(parts)
    return _not(u) if negate else u


def _seq(nodes: list, ctx: Ctx) -> z3.ReRef:
    return _concat([_node(op, av, ctx) for op, av in nodes])


def _node(op: Any, av: Any, ctx: Ctx) -> z3.ReRef:
    if op == sre_c.LITERAL:
        return _lit(av)
    if op == sre_c.NOT_LITERAL:
        return _not(_lit(av))
    if op == sre_c.ANY:  # without DOTALL, '.' does not match '\n'
        return _not(_lit(10))
    if op == sre_c.IN:
        return _class(list(av), ctx)
    if op == sre_c.CATEGORY:
        return _category(av, ctx)
    if op == sre_c.SUBPATTERN:
        _group, add_flags, del_flags, sub = av
        if add_flags or del_flags:
            raise Unsupported("inline regex flags inside a group")
        return _seq(list(sub), ctx)
    if op == sre_c.BRANCH:
        return _union([_seq(list(b), ctx) for b in av[1]])
    if op in (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT):
        # Lazy vs greedy does not change which strings match somewhere.
        lo, hi, sub = av
        r = _seq(list(sub), ctx)
        if hi == sre_c.MAXREPEAT:
            if lo == 0:
                return z3.Star(r)
            return z3.Concat(z3.Loop(r, lo, lo), z3.Star(r)) if lo > 1 else z3.Plus(r)
        if hi == 0:
            return z3.Re(z3.StringVal(""))
        return z3.Loop(r, lo, hi)
    if op == sre_c.AT:
        raise Unsupported("an anchor or word boundary in the middle of a pattern")
    raise Unsupported(f"regex construct {op}")


def pattern_search_language(pattern: str, ctx: Ctx) -> z3.ReRef:
    """The set of strings s for which re.search(pattern, s) succeeds."""
    try:
        parsed = sre_parse.parse(pattern)
    except re.error as e:
        raise Unsupported(f"invalid regex: {e}") from e
    if parsed.state.flags & ~(sre_c.SRE_FLAG_UNICODE):
        raise Unsupported("regex flags such as (?i), (?m), (?s)")
    nodes = list(parsed)
    if len(nodes) == 1 and nodes[0][0] == sre_c.BRANCH:
        branches = [list(b) for b in nodes[0][1][1]]
    else:
        branches = [nodes]
    return _union([_search_branch(b, ctx) for b in branches])


def _search_branch(nodes: list, ctx: Ctx) -> z3.ReRef:
    full = z3.Full(STR_RE)
    start_anchored = bool(nodes) and nodes[0] == (sre_c.AT, sre_c.AT_BEGINNING) or (
        bool(nodes) and nodes[0] == (sre_c.AT, sre_c.AT_BEGINNING_STRING)
    )
    if start_anchored:
        nodes = nodes[1:]
    end = None
    if nodes and nodes[-1] == (sre_c.AT, sre_c.AT_END):
        end, nodes = "dollar", nodes[:-1]
    elif nodes and nodes[-1] == (sre_c.AT, sre_c.AT_END_STRING):
        end, nodes = "Z", nodes[:-1]
    core = _seq(nodes, ctx)
    prefix = [] if start_anchored else [full]
    if end is None:
        suffix = [full]
    elif end == "dollar":  # Python's $ also matches just before a final '\n'
        suffix = [z3.Option(_lit(10))]
    else:
        suffix = []
    return _concat(prefix + [core] + suffix)


# --------------------------------------------------------------------------- types and values

ARG_TYPES = ("string", "integer", "number", "boolean", "array<string>", "array<integer>")


def _schema_type(schema: dict) -> str | None:
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), None)
    if t == "array":
        it = schema.get("items")
        inner = _schema_type(it) if isinstance(it, dict) else None
        return "array<integer>" if inner == "integer" else "array<string>"
    if t in ("string", "integer", "number", "boolean"):
        return t
    for key in ("anyOf", "oneOf", "allOf"):
        for sub in schema.get(key, []) or []:
            if isinstance(sub, dict) and (st := _schema_type(sub)):
                return st
    vals = schema.get("enum") or ([schema["const"]] if "const" in schema else None)
    if vals:
        v = vals[0]
        if isinstance(v, bool):
            return "boolean"
        if isinstance(v, int):
            return "integer"
        if isinstance(v, float):
            return "number"
        if isinstance(v, list):
            return "array<integer>" if v and isinstance(v[0], int) else "array<string>"
        return "string"
    if any(k in schema for k in ("pattern", "minLength", "maxLength", "format")):
        return "string"
    if any(k in schema for k in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf")):
        return "number"
    if any(k in schema for k in ("items", "minItems", "maxItems")):
        return "array<string>"
    return None


def infer_arg_types(policies: list[Policy], tool_schemas: dict[str, dict] | None) -> dict[str, dict[str, str]]:
    types: dict[str, dict[str, str]] = {}
    for tool, props in (tool_schemas or {}).items():
        for arg, sch in props.items():
            if isinstance(sch, dict) and (t := _schema_type(sch)):
                types.setdefault(tool, {})[arg] = t
    for pol in policies:
        for tool, rules in pol.items():
            for r in rules:
                for arg, sch in r["conditions"].items():
                    if arg not in types.get(tool, {}):
                        types.setdefault(tool, {})[arg] = _schema_type(sch) or "string"
    return types


def _mkvar(name: str, typ: str) -> z3.ExprRef:
    return {
        "string": lambda: z3.String(name),
        "integer": lambda: z3.Int(name),
        "number": lambda: z3.Real(name),
        "boolean": lambda: z3.Bool(name),
        "array<string>": lambda: z3.Const(name, z3.SeqSort(z3.StringSort())),
        "array<integer>": lambda: z3.Const(name, z3.SeqSort(z3.IntSort())),
    }[typ]()


def _val(v: Any, typ: str) -> z3.ExprRef | None:
    """A Python value as a Z3 term of `typ`, or None if jsonschema would never consider them equal."""
    if typ == "string":
        return z3.StringVal(v) if isinstance(v, str) else None
    if typ == "boolean":
        return z3.BoolVal(v) if isinstance(v, bool) else None
    if typ == "integer":
        if isinstance(v, bool):
            return None
        if isinstance(v, int) or (isinstance(v, float) and v.is_integer()):
            return z3.IntVal(int(v))
        return None
    if typ == "number":
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None
        return z3.RealVal(str(Fraction(v)))
    if typ.startswith("array<"):
        if not isinstance(v, list):
            return None
        inner = "integer" if typ == "array<integer>" else "string"
        sort = z3.IntSort() if inner == "integer" else z3.StringSort()
        elems = [_val(x, inner) for x in v]
        if any(e is None for e in elems):
            return None
        if not elems:
            return z3.Empty(z3.SeqSort(sort))
        units = [z3.Unit(e) for e in elems]
        return units[0] if len(units) == 1 else z3.Concat(*units)
    return None


def _type_ok(json_type: str, typ: str, x: z3.ExprRef) -> z3.BoolRef:
    if json_type == "string":
        return z3.BoolVal(typ == "string")
    if json_type == "integer":
        if typ == "integer":
            return z3.BoolVal(True)
        if typ == "number":
            return z3.IsInt(x)
        return z3.BoolVal(False)
    if json_type == "number":
        return z3.BoolVal(typ in ("integer", "number"))
    if json_type == "boolean":
        return z3.BoolVal(typ == "boolean")
    if json_type == "array":
        return z3.BoolVal(typ.startswith("array<"))
    if json_type in ("null", "object"):
        return z3.BoolVal(False)
    raise Unsupported(f"type '{json_type}'")


# --------------------------------------------------------------------------- schema -> constraint


def encode(schema: dict, x: z3.ExprRef, typ: str, ctx: Ctx) -> z3.BoolRef:
    """Constraint that holds exactly when jsonschema accepts value x (of argument type typ)."""
    if not isinstance(schema, dict):
        raise Unsupported("a condition that is not a JSON Schema object")
    cs: list[z3.BoolRef] = []
    is_str, is_num = typ == "string", typ in ("integer", "number")
    is_arr = typ.startswith("array<")
    for key, val in schema.items():
        if key in IGNORED_KEYWORDS:
            continue
        if key == "type":
            ts = val if isinstance(val, list) else [val]
            cs.append(z3.Or(*[_type_ok(t, typ, x) for t in ts]) if ts else z3.BoolVal(False))
        elif key in ("enum", "const"):
            vals = val if key == "enum" else [val]
            terms = [t for t in (_val(v, typ) for v in vals) if t is not None]
            cs.append(z3.Or(*[x == t for t in terms]) if terms else z3.BoolVal(False))
        elif key == "pattern":
            if is_str:
                cs.append(z3.InRe(x, pattern_search_language(val, ctx)))
        elif key in ("minLength", "maxLength"):
            if is_str:
                cs.append(z3.Length(x) >= val if key == "minLength" else z3.Length(x) <= val)
        elif key == "format":
            ctx.warn(
                f"'format: {val}' is ignored: jsonschema.validate() does not check formats unless a "
                "FormatChecker is passed, and the reference enforcer does not pass one."
            )
        elif key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise Unsupported(f"non-numeric {key} (draft-4 boolean form)")
            if is_num:
                bound = z3.RealVal(str(Fraction(val)))
                xr = z3.ToReal(x) if typ == "integer" else x
                cs.append(
                    {"minimum": xr >= bound, "maximum": xr <= bound,
                     "exclusiveMinimum": xr > bound, "exclusiveMaximum": xr < bound}[key]
                )
        elif key == "multipleOf":
            if is_num:
                xr = z3.ToReal(x) if typ == "integer" else x
                cs.append(z3.IsInt(xr / z3.RealVal(str(Fraction(val)))))
        elif key in ("minItems", "maxItems"):
            if is_arr:
                cs.append(z3.Length(x) >= val if key == "minItems" else z3.Length(x) <= val)
        elif key == "items":
            if is_arr:
                if not isinstance(val, dict):
                    raise Unsupported("tuple-form 'items'")
                inner = "integer" if typ == "array<integer>" else "string"
                i = z3.Int(f"i_{id(val)}")
                cs.append(
                    z3.ForAll([i], z3.Implies(z3.And(i >= 0, i < z3.Length(x)), encode(val, x[i], inner, ctx)))
                )
        elif key == "anyOf":
            cs.append(z3.Or(*[encode(s, x, typ, ctx) for s in val]))
        elif key == "allOf":
            cs.append(z3.And(*[encode(s, x, typ, ctx) for s in val]))
        elif key == "oneOf":
            subs = [encode(s, x, typ, ctx) for s in val]
            cs.append(z3.Sum([z3.If(s, 1, 0) for s in subs]) == 1)
        elif key == "not":
            cs.append(z3.Not(encode(val, x, typ, ctx)))
        else:
            raise Unsupported(f"JSON Schema keyword '{key}'")
    return z3.And(*cs) if cs else z3.BoolVal(True)


def allowed_formula(rules: list[dict], vars_: dict[str, z3.ExprRef], types: dict[str, str], ctx: Ctx) -> z3.BoolRef:
    """Algorithm 2 as a formula: first matching rule wins; default deny."""
    ordered = sorted(rules, key=lambda r: (r["priority"], 0 if r["effect"] == "forbid" else 1))
    disjuncts = []
    earlier: list[z3.BoolRef] = []
    for r in ordered:
        m = z3.And(*[encode(s, vars_[a], types[a], ctx) for a, s in r["conditions"].items()]) if r["conditions"] else z3.BoolVal(True)
        if r["effect"] == "allow":
            disjuncts.append(z3.And(m, *[z3.Not(e) for e in earlier]))
        earlier.append(m)
    return z3.Or(*disjuncts) if disjuncts else z3.BoolVal(False)


# --------------------------------------------------------------------------- comparison


_Z3_ESC = re.compile(r"\\u\{([0-9a-fA-F]+)\}")


def _z3str(v: z3.ExprRef) -> str:
    """Decode Z3's escaped string literal (it renders non-printables as \\u{hex})."""
    return _Z3_ESC.sub(lambda m: chr(int(m.group(1), 16)), v.as_string())


def _py_value(model: z3.ModelRef, x: z3.ExprRef, typ: str) -> Any:
    v = model.eval(x, model_completion=True)
    if typ == "string":
        return _z3str(v)
    if typ == "integer":
        return v.as_long()
    if typ == "number":
        f = v.as_fraction()
        return int(f) if f.denominator == 1 else float(f)
    if typ == "boolean":
        return z3.is_true(v)
    inner = "integer" if typ == "array<integer>" else "string"
    n = model.eval(z3.Length(x), model_completion=True).as_long()
    out = []
    for i in range(min(n, 20)):
        e = model.eval(x[i], model_completion=True)
        out.append(e.as_long() if inner == "integer" else _z3str(e))
    return out


ATTACKER_HINTS = ("eve@evil.com", "evil.com", "evil")


def _clean(s: str) -> list[str]:
    """Readable variants of a solver string: control characters dropped or replaced."""
    out = []
    dropped = "".join(c for c in s if c.isprintable() or c == "\n")
    if dropped != s:
        out.append(dropped)
    replaced = "".join(c if (c.isprintable() or c == "\n") else "x" for c in s)
    if replaced not in out and replaced != s:
        out.append(replaced)
    return out


def _readable_model(formula: z3.BoolRef, vars_: dict[str, z3.ExprRef], types: dict[str, str],
                    constrained: set[str]) -> z3.ModelRef | None:
    """Prefer witnesses a person can read: attacker-flavoured and free of control characters.

    Constraining strings to printable ASCII inside the query makes Z3's regex
    solver slow, so instead: get a fast model, clean its strings, and re-verify
    the cleaned values against the formula (cheap, all values concrete)."""
    strs = {a: v for a, v in vars_.items() if types[a] == "string"}
    targets = [v for a, v in strs.items() if a in constrained] or list(strs.values())
    if not strs:
        return None
    attempts = [[z3.Or(*[z3.Contains(v, z3.StringVal(h)) for v in targets])] for h in ATTACKER_HINTS]
    attempts.append([z3.And(*[z3.Length(v) >= 3 for v in targets])])
    for extra in attempts:
        res, s = _check(z3.And(formula, *extra), 1000)
        if res != z3.sat:
            continue
        m = s.model()
        raw = {a: _z3str(m.eval(v, model_completion=True)) for a, v in strs.items()}
        if all(x.isprintable() for x in raw.values()):
            return m
        # Try cleaned variants, pinning every other variable to its model value.
        pins = [v == m.eval(v, model_completion=True) for a, v in vars_.items() if a not in strs]
        for variant in range(2):
            cand = {}
            for a, x in raw.items():
                opts = _clean(x)
                cand[a] = opts[min(variant, len(opts) - 1)] if opts else x
            fixed = [strs[a] == z3.StringVal(c) for a, c in cand.items()]
            res2, s2 = _check(z3.And(formula, *pins, *fixed), 1000)
            if res2 == z3.sat:
                return s2.model()
    return None


def _check(formula: z3.BoolRef, timeout_ms: int) -> tuple[z3.CheckSatResult, z3.Solver]:
    s = z3.Solver()
    s.set("timeout", timeout_ms)
    s.add(formula)
    return s.check(), s


def compare(old: Policy, new: Policy, tool_schemas: dict[str, dict] | None = None) -> dict[str, Any]:
    """Is A(new) ⊆ A(old)? Per tool, look for a call allowed by new and denied by old."""
    types = infer_arg_types([old, new], tool_schemas)
    tools = sorted(set(old) | set(new))
    per_tool = []
    with Z3_LOCK:
        for tool in tools:
            ctx = Ctx()
            entry: dict[str, Any] = {"tool": tool}
            ttypes = types.get(tool, {})
            vars_ = {a: _mkvar(f"{tool}.{a}", t) for a, t in ttypes.items()}
            try:
                a_old = allowed_formula(old.get(tool, []), vars_, ttypes, ctx)
                a_new = allowed_formula(new.get(tool, []), vars_, ttypes, ctx)
            except Unsupported as e:
                entry.update(verdict="expansion", basis="unsupported", detail=f"Cannot model {e}; treated as an expansion (fail closed).")
                entry["warnings"] = ctx.warnings
                per_tool.append(entry)
                continue
            res, solver = _check(z3.And(a_new, z3.Not(a_old)), SOLVER_TIMEOUT_MS)
            entry["smt"] = solver.sexpr()[-6000:]
            if res == z3.sat:
                constrained = {a for p in (old, new) for r in p.get(tool, []) for a in r["conditions"]}
                m = _readable_model(z3.And(a_new, z3.Not(a_old)), vars_, ttypes, constrained) or solver.model()
                witness = {a: _py_value(m, v, ttypes[a]) for a, v in vars_.items()}
                entry.update(verdict="expansion", basis="witness", witness=witness,
                             detail="Found a call the new policy allows and the old policy denies.")
            elif res == z3.unsat:
                rev, _ = _check(z3.And(a_old, z3.Not(a_new)), 3000)
                entry.update(verdict="narrowing", basis="proof",
                             strict=True if rev == z3.sat else (False if rev == z3.unsat else None),
                             detail="No call is allowed by the new policy that the old policy denies.")
            else:
                entry.update(verdict="expansion", basis="unknown",
                             detail=f"Solver returned unknown ({solver.reason_unknown()}); treated as an expansion (fail closed).")
            entry["types"] = ttypes
            entry["warnings"] = ctx.warnings
            per_tool.append(entry)
    overall = "narrowing" if all(t["verdict"] == "narrowing" for t in per_tool) else "expansion"
    return {"narrowing": overall == "narrowing", "verdict": overall, "tools": per_tool}


# --------------------------------------------------------------------------- concrete enforcement


def evaluate_call(policy: Policy, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    """Algorithm 2 on a concrete call, with jsonschema doing each condition (absent args are skipped,
    as in the reference enforcer)."""
    rules = policy.get(tool, [])
    ordered = sorted(enumerate(rules), key=lambda ir: (ir[1]["priority"], 0 if ir[1]["effect"] == "forbid" else 1))
    for idx, r in ordered:
        failed = None
        for arg, sch in r["conditions"].items():
            if arg in args:
                v = jsonschema.Draft202012Validator(sch)
                errs = list(v.iter_errors(args[arg]))
                if errs:
                    failed = f"argument '{arg}': {errs[0].message}"
                    break
        if failed is None:
            return {"allowed": r["effect"] == "allow", "rule": idx, "effect": r["effect"],
                    "reason": None if r["effect"] == "allow" else f"matched forbid rule #{idx}"}
    return {"allowed": False, "rule": None, "effect": None, "reason": f"no rule for '{tool}' matched (default deny)"}


def validate_schemas(policy: Policy) -> list[str]:
    errors = []
    for tool, rules in policy.items():
        for i, r in enumerate(rules):
            for arg, sch in r["conditions"].items():
                try:
                    jsonschema.Draft202012Validator.check_schema(sch)
                except jsonschema.SchemaError as e:
                    errors.append(f"{tool} rule #{i}, '{arg}': invalid JSON Schema ({e.message})")
    return errors
