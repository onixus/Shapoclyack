"""Bounded, side-effect-free dynamic asset group rules.

Rules consume registered inventory only. Three-valued logic prevents missing
evidence from becoming a positive match through negation. Assignment precedence
and audited persistence belong to the group service, in one transaction.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from api.services.assets import CONTEXT_FIELDS, DATA_CLASSIFICATIONS, ENVIRONMENTS, EXPOSURE_LEVELS

MAX_DEPTH = 4
MAX_NODES = 100
MAX_VALUES = 50
MAX_STRING = 256
MAX_RULE_BYTES = 16384
_TAG = re.compile(r"tag:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_FIELDS = frozenset((*CONTEXT_FIELDS, "ip", "fqdn", "status"))
_OPS = frozenset(("eq", "ne", "in", "not_in", "contains", "starts_with", "ends_with", "cidr"))
_INTEGERS = frozenset(("asset_criticality",))
_ENUMS = {"environment": ENVIRONMENTS, "data_classification": DATA_CLASSIFICATIONS,
          "exposure_level": EXPOSURE_LEVELS, "status": ("active", "stale", "decommissioned")}


def _scalar(field: str, value: Any) -> Any:
    if field in _INTEGERS:
        low, high = 0, 4
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{field} must be an integer {low}-{high}")
        return value
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_STRING:
        raise ValueError(f"{field} must be a nonempty string of at most {MAX_STRING} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{field} cannot contain control characters")
    if field in _ENUMS and value not in _ENUMS[field]:
        raise ValueError(f"invalid {field} value")
    if field == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("ip requires an IP address") from exc
    return value


def validate_rules(rules: dict[str, Any]) -> dict[str, Any]:
    """Return a detached canonical rule tree or raise ``ValueError``.

    Group nodes contain exactly ``all`` or ``any`` and may be negated. Leaves
    contain field, op and value, optionally negate. No executable expressions,
    regular expressions, implicit type conversions or OS guesses are accepted.
    """
    count = 0

    def visit(node: Any, depth: int) -> dict[str, Any]:
        nonlocal count
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise ValueError("rule tree exceeds depth or node limit")
        if not isinstance(node, dict):
            raise ValueError("each rule must be an object")
        negate = node.get("negate", False)
        if type(negate) is not bool:
            raise ValueError("negate must be a boolean")
        branches = set(node) & {"all", "any"}
        if branches:
            if len(branches) != 1 or set(node) - branches - {"negate"}:
                raise ValueError("a branch requires exactly one of all/any")
            kind = next(iter(branches))
            children = node[kind]
            if not isinstance(children, list) or not 1 <= len(children) <= MAX_VALUES:
                raise ValueError("a branch needs 1-50 child rules")
            out = {kind: [visit(child, depth + 1) for child in children]}
        else:
            if set(node) - {"field", "op", "value", "negate"} or not {"field", "op", "value"} <= set(node):
                raise ValueError("a condition requires field, op and value")
            field, op, value = node["field"], node["op"], node["value"]
            if not isinstance(field, str) or (field not in _FIELDS and not _TAG.fullmatch(field)):
                raise ValueError("unsupported rule field")
            if not isinstance(op, str) or op not in _OPS:
                raise ValueError("unsupported rule operator")
            if field in _INTEGERS and op not in {"eq", "ne", "in", "not_in"}:
                raise ValueError("integer fields only support eq/ne/in/not_in")
            if field == "ip" and op not in {"eq", "ne", "in", "not_in", "cidr"}:
                raise ValueError("IP fields only support eq/ne/in/not_in/cidr")
            if op == "cidr":
                if field != "ip" or not isinstance(value, str) or len(value) > MAX_STRING:
                    raise ValueError("cidr requires the ip field and a network")
                try:
                    value = str(ipaddress.ip_network(value, strict=False))
                except ValueError as exc:
                    raise ValueError("invalid IP network") from exc
            elif op in {"in", "not_in"}:
                if not isinstance(value, list) or not 1 <= len(value) <= MAX_VALUES:
                    raise ValueError("in/not_in require 1-50 values")
                value = [_scalar(field, item) for item in value]
            else:
                value = _scalar(field, value)
            out = {"field": field, "op": op, "value": value}
        if negate:
            out["negate"] = True
        return out

    normalized = visit(rules, 0)
    if len(json.dumps(normalized, ensure_ascii=False).encode()) > MAX_RULE_BYTES:
        raise ValueError("rule tree exceeds byte limit")
    return normalized


def validate_context(context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(context, dict) or set(context) - (set(CONTEXT_FIELDS) - {"exposure_level"}):
        raise ValueError("context contains unsupported fields")
    out = {field: _scalar(field, value) for field, value in context.items()}
    for field, limit in {"owner_email": 254, "business_unit": 200, "business_service": 200}.items():
        if field in out and len(out[field]) > limit:
            raise ValueError(f"{field} exceeds {limit} characters")
    if "owner_email" in out and not re.fullmatch(r"[^@\s]+@[^@\s]+", out["owner_email"]):
        raise ValueError("owner_email must be an email address")
    if any(isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")) for value in out.values()):
        raise ValueError("context cannot start with a spreadsheet formula prefix")
    return out


def _fold(values: list[bool | None], *, all_: bool) -> bool | None:
    decisive = False if all_ else True
    if decisive in values:
        return decisive
    return None if None in values else not decisive


def evaluate_rules(rules: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    rules = validate_rules(rules)
    reasons: list[dict[str, Any]] = []

    def condition(node: dict[str, Any]) -> bool | None:
        field, op, expected = node["field"], node["op"], node["value"]
        raw = snapshot.get(field)
        if field.startswith("tag:") and field not in snapshot:
            tags = snapshot.get("tags")
            raw = tags.get(field[4:]) if isinstance(tags, dict) else None
        values = raw if isinstance(raw, (list, tuple)) else [raw]
        results: list[bool | None] = []
        for actual in values:
            if actual is None or actual == "" or actual == "unknown":
                results.append(None)
                continue
            try:
                actual = _scalar(field, actual)
            except ValueError:
                results.append(None)
                continue
            if op == "cidr":
                result = ipaddress.ip_address(actual) in ipaddress.ip_network(expected)
            else:
                def normalized(value: Any) -> Any:
                    if isinstance(value, str):
                        return value.rstrip(".").casefold() if field == "fqdn" else value.casefold()
                    return value
                actual = normalized(actual)
                target = [normalized(item) for item in expected] if isinstance(expected, list) else normalized(expected)
                if op in {"eq", "ne"}:
                    result = actual == target
                elif op in {"in", "not_in"}:
                    result = actual in target
                elif op == "contains":
                    result = target in actual
                elif op == "starts_with":
                    result = actual.startswith(target)
                else:
                    result = actual.endswith(target)
                if op in {"ne", "not_in"}:
                    result = not result
            results.append(result)
        result = _fold(results or [None], all_=op in {"ne", "not_in"})
        effective = not result if node.get("negate") and result is not None else result
        reasons.append({"field": field, "op": op, "value": expected,
                        "actual": values[:MAX_VALUES], "negate": node.get("negate", False),
                        "actual_truncated": len(values) > MAX_VALUES,
                        "result": "unknown" if effective is None else "matched" if effective else "not_matched"})
        return result

    def visit(node: dict[str, Any]) -> bool | None:
        if "all" in node or "any" in node:
            kind = "all" if "all" in node else "any"
            result = _fold([visit(child) for child in node[kind]], all_=kind == "all")
        else:
            result = condition(node)
        return not result if node.get("negate") and result is not None else result

    result = visit(rules)
    return {"matched": result is True, "result": "unknown" if result is None else "matched" if result else "not_matched", "reasons": reasons}

