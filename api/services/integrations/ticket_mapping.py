"""Field mapping, text templates and routing for ticket transports (#353).

``tickets.py`` used to hard-code the subject, the description and the Jira
fields. This module is the configurable half: everything an operator may set in
``transport_config`` beyond the adapter's own required knobs.

SAFETY: a template is plain text with ``{placeholder}`` tokens from a closed
list. It is never passed to ``str.format``, ``eval`` or a template engine, so a
tenant admin cannot reach attributes, call anything or read anything the event
did not already carry. An unknown placeholder is refused when the subscription
is saved, not discovered as a dead-lettered delivery. Substituted values come
from scanner output (banners, script ids) and are therefore stripped of control
characters and capped before they reach a tracker.

Nothing here touches the network or the database: asset context is looked up by
the caller and handed in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from scanner.pipeline.report import SEVERITY_ORDER

#: Names a template may use. Closed on purpose: adding one is a code change that
#: has to say where the value comes from.
PLACEHOLDERS = (
    "kind",
    "host",
    "port",
    "where",
    "cve",
    "severity",
    "cvss",
    "script_id",
    "run_id",
    "business_unit",
    "environment",
    "criticality",
    "owner",
)

_TOKEN = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FIELD_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

MAX_TEMPLATE_CHARS = 4000
MAX_VALUE_CHARS = 500
MAX_LIST_ITEMS = 20
MAX_ITEM_CHARS = 64
MAX_CUSTOM_FIELDS = 20
MAX_TARGET_RULES = 50

#: Jira fields this module owns; a custom field may not overwrite them.
_RESERVED_JIRA_FIELDS = frozenset(
    {"project", "issuetype", "summary", "description", "priority", "labels", "components"}
)

#: Transports whose "where does the ticket go" knob can be rerouted by a rule,
#: and the ``transport_config`` key that knob lives under.
TARGET_KEYS = {
    "jira": "project_key",
    "github": "repository",
    "gitlab": "project",
    "defectdojo": "test_id",
}


class MappingError(ValueError):
    """The mapping section of ``transport_config`` is invalid."""


# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------


def validate_template(name: str, value: Any) -> str | None:
    """``None`` for unset; otherwise the template, with unknown tokens refused."""
    if value is None or str(value).strip() == "":
        return None
    text = str(value)
    if len(text) > MAX_TEMPLATE_CHARS:
        raise MappingError(f"{name} must be at most {MAX_TEMPLATE_CHARS} characters")
    unknown = sorted({m for m in _TOKEN.findall(text) if m not in PLACEHOLDERS})
    if unknown:
        raise MappingError(
            f"{name} uses unknown placeholder(s) {', '.join('{' + u + '}' for u in unknown)}; "
            f"allowed: {', '.join(PLACEHOLDERS)}"
        )
    return text


def _clean(value: Any, *, single_line: bool = False) -> str:
    if value is None:
        return ""
    text = _CONTROL.sub("", str(value))[:MAX_VALUE_CHARS]
    if single_line:
        # Jira refuses a summary or a single-line field holding a newline, and
        # that is a dead-lettered delivery rather than a ticket.
        text = _WHITESPACE.sub(" ", text).strip()
    return text


_WHITESPACE = re.compile(r"\s+")
_MD_ACTIVE = re.compile(r"([\\`*_\[\]()<>#!|~%$&])")


def markdown_escape(text: str) -> str:
    """Make scanner-supplied text inert in GitHub/GitLab Markdown.

    Banners and script ids are attacker-influenced. Unescaped, a value such as
    ``@org/security`` pings people, ``#12`` links an unrelated issue and
    ``[x](https://...)`` plants a link in a ticket the SOC trusts.
    """
    # One line only: GitLab quick actions (``/close``, ``/assign @x``) act on a
    # line that starts with them, and a banner containing a newline could start
    # one. ``%``, ``$``, ``&`` and ``~`` are GitLab reference sigils
    # (milestone, snippet, epic, label).
    text = _WHITESPACE.sub(" ", text).strip()
    text = _MD_ACTIVE.sub(r"\\\1", text).replace("@", "&#64;")
    return "\\" + text if text.startswith("/") else text


def render(template: str, context: dict[str, str]) -> str:
    """Substitute ``{name}`` tokens; anything that is not a token stays as is."""
    return _TOKEN.sub(lambda m: context.get(m.group(1), m.group(0)), template)


def build_context(
    envelope: dict[str, Any],
    asset: dict[str, Any] | None,
    *,
    single_line: bool = False,
    markdown: bool = False,
) -> dict[str, str]:
    """Placeholder values for one event. Missing values render as ``-``.

    ``single_line`` is for summaries and single-line fields (newlines, tabs
    collapse to a space); ``markdown`` escapes Markdown-active text for
    GitHub / GitLab bodies.
    """
    data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
    asset = asset or {}

    def pick(*values: Any) -> str:
        for value in values:
            if value not in (None, ""):
                text = _clean(value, single_line=single_line)
                return markdown_escape(text) if markdown else text
        return "-"

    host = pick(envelope.get("host"), data.get("host"))
    port = pick(envelope.get("port"), data.get("port"))
    where = host if port == "-" else f"{host}:{port}"
    return {
        "kind": pick(envelope.get("kind")),
        "host": host,
        "port": port,
        "where": where,
        "cve": pick(data.get("cve"), envelope.get("cve")),
        "severity": pick(str(data.get("severity") or "").lower()),
        "cvss": pick(data.get("cvss")),
        "script_id": pick(data.get("script_id")),
        "run_id": pick(envelope.get("run_id")),
        "business_unit": pick(asset.get("business_unit")),
        "environment": pick(asset.get("environment")),
        "criticality": pick(asset.get("criticality")),
        "owner": pick(asset.get("owner")),
    }


# --------------------------------------------------------------------------
# Validation of the mapping section
# --------------------------------------------------------------------------


def strict_bool(name: str, value: Any, default: bool) -> bool:
    """A JSON boolean or nothing. ``"false"`` is a mistake, not ``True``."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise MappingError(f"{name} must be true or false")


#: Transports whose create call has a label concept.
LABEL_TRANSPORTS = ("jira", "github", "gitlab")
#: ServiceNow ``urgency`` values.
SNOW_URGENCIES = ("1", "2", "3")


def _string_list(name: str, value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, (list, tuple)):
        raise MappingError(f"{name} must be a list of strings")
    out: list[str] = []
    for item in value:
        text = _CONTROL.sub("", str(item)).strip()
        if not text:
            continue
        if len(text) > MAX_ITEM_CHARS:
            raise MappingError(f"{name} entries must be at most {MAX_ITEM_CHARS} characters")
        if text not in out:
            out.append(text)
    if len(out) > MAX_LIST_ITEMS:
        raise MappingError(f"{name} may have at most {MAX_LIST_ITEMS} entries")
    return out


def _severity_name(value: Any, where: str) -> str:
    name = str(value or "").strip().lower()
    if name not in SEVERITY_ORDER:
        raise MappingError(f"{where}: unknown severity {value!r}; expected one of {', '.join(SEVERITY_ORDER)}")
    return name


def _validate_custom_fields(transport: str, raw: Any) -> dict[str, Any]:
    if raw in (None, {}):
        return {}
    if transport != "jira":
        raise MappingError(f"custom_fields is only supported for jira, not {transport}")
    if not isinstance(raw, dict):
        raise MappingError("custom_fields must be an object")
    if len(raw) > MAX_CUSTOM_FIELDS:
        raise MappingError(f"custom_fields may have at most {MAX_CUSTOM_FIELDS} entries")
    out: dict[str, Any] = {}
    for key, value in raw.items():
        name = str(key)
        if not _FIELD_KEY.match(name):
            raise MappingError(f"custom_fields key {name!r} is not a field id")
        if name in _RESERVED_JIRA_FIELDS:
            raise MappingError(f"custom_fields may not set {name!r}; it has its own setting")
        if isinstance(value, bool) or isinstance(value, (int, float)):
            out[name] = value
        elif isinstance(value, str):
            out[name] = validate_template(f"custom_fields.{name}", value) or ""
        elif isinstance(value, list) and all(isinstance(v, str) for v in value):
            out[name] = [validate_template(f"custom_fields.{name}", v) or "" for v in value]
        else:
            raise MappingError(
                f"custom_fields.{name} must be a string, number, boolean or list of strings"
            )
    return out


def _validate_severity_rules(transport: str, raw: Any) -> dict[str, dict[str, Any]]:
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        raise MappingError("severity_rules must be an object keyed by severity")
    out: dict[str, dict[str, Any]] = {}
    for key, rule in raw.items():
        severity = _severity_name(key, "severity_rules")
        if not isinstance(rule, dict):
            raise MappingError(f"severity_rules.{severity} must be an object")
        unknown = set(rule) - {"create", "priority", "labels"}
        if unknown:
            raise MappingError(
                f"severity_rules.{severity} has unknown key(s) {', '.join(sorted(unknown))}"
            )
        clean: dict[str, Any] = {
            "create": strict_bool(f"severity_rules.{severity}.create", rule.get("create"), True)
        }
        priority = str(rule.get("priority") or "").strip()
        if priority:
            if len(priority) > MAX_ITEM_CHARS:
                raise MappingError(f"severity_rules.{severity}.priority is too long")
            if transport == "servicenow" and priority not in SNOW_URGENCIES:
                raise MappingError(
                    f"severity_rules.{severity}.priority must be one of "
                    f"{', '.join(SNOW_URGENCIES)} (ServiceNow urgency)"
                )
            clean["priority"] = priority
        labels = _string_list(f"severity_rules.{severity}.labels", rule.get("labels"))
        if labels:
            if transport not in LABEL_TRANSPORTS:
                raise MappingError(f"severity_rules.{severity}.labels is not supported for {transport}")
            clean["labels"] = labels
        out[severity] = clean
    return out


def _validate_target_rules(
    transport: str, raw: Any, validate_target
) -> list[dict[str, Any]]:
    if raw in (None, []):
        return []
    if transport not in TARGET_KEYS:
        raise MappingError(f"target_rules are not supported for {transport}")
    if not isinstance(raw, list):
        raise MappingError("target_rules must be a list")
    if len(raw) > MAX_TARGET_RULES:
        raise MappingError(f"target_rules may have at most {MAX_TARGET_RULES} entries")
    out: list[dict[str, Any]] = []
    for index, rule in enumerate(raw):
        where = f"target_rules[{index}]"
        if not isinstance(rule, dict):
            raise MappingError(f"{where} must be an object")
        unknown = set(rule) - {
            "business_unit",
            "environment",
            "min_criticality",
            "max_criticality",
            "severities",
            "target",
            "labels",
        }
        if unknown:
            raise MappingError(f"{where} has unknown key(s) {', '.join(sorted(unknown))}")
        clean: dict[str, Any] = {"target": validate_target(rule.get("target"))}
        for key in ("business_unit", "environment"):
            text = str(rule.get(key) or "").strip()
            if text:
                clean[key] = text[:MAX_ITEM_CHARS]
        for key in ("min_criticality", "max_criticality"):
            if rule.get(key) not in (None, ""):
                try:
                    clean[key] = int(rule[key])
                except (TypeError, ValueError) as exc:
                    raise MappingError(f"{where}.{key} must be an integer") from exc
        severities = rule.get("severities")
        if severities not in (None, []):
            if not isinstance(severities, list):
                raise MappingError(f"{where}.severities must be a list")
            clean["severities"] = sorted({_severity_name(s, where) for s in severities})
        labels = _string_list(f"{where}.labels", rule.get("labels"))
        if labels:
            if transport not in LABEL_TRANSPORTS:
                raise MappingError(f"{where}.labels is not supported for {transport}")
            clean["labels"] = labels
        # A rule with no condition would shadow every rule after it.
        if not set(clean) - {"target", "labels"}:
            raise MappingError(f"{where} needs at least one condition")
        out.append(clean)
    return out


def _refuse_placeholders_in_code(template: str) -> None:
    """GitHub / GitLab descriptions are Markdown; code is where escaping breaks.

    Scan-derived values are escaped for Markdown prose. Inside a code span or
    fence that escaping would print literally, and *not* escaping would let a
    value close the span with a backtick and continue as prose. Whether a
    placeholder sits inside code cannot be told reliably (double-backtick spans,
    fences, indentation), so a template that mixes a backtick with a
    placeholder is refused instead of guessed at.
    """
    if "`" in template and _TOKEN.search(template):
        raise MappingError(
            "description_template may not use placeholders together with backticks "
            "(code spans or fences); write the values as plain text"
        )


def validate_mapping(transport: str, cfg: dict[str, Any], validate_target) -> dict[str, Any]:
    """The normalised mapping keys of ``cfg``; only keys that are set appear.

    ``validate_target`` is the transport's own check for its target knob
    (project key, repository, project path, test id), so a rule cannot route to
    something the base config would have refused.
    """
    out: dict[str, Any] = {}
    for key in ("summary_template", "description_template"):
        template = validate_template(key, cfg.get(key))
        if template:
            if key == "description_template" and transport in ("github", "gitlab"):
                _refuse_placeholders_in_code(template)
            out[key] = template
    labels = _string_list("labels", cfg.get("labels"))
    if labels:
        if transport not in LABEL_TRANSPORTS:
            raise MappingError(f"labels is not supported for {transport}")
        out["labels"] = labels
    components = _string_list("components", cfg.get("components"))
    if components:
        if transport != "jira":
            raise MappingError(f"components is only supported for jira, not {transport}")
        out["components"] = components
    custom = _validate_custom_fields(transport, cfg.get("custom_fields"))
    if custom:
        out["custom_fields"] = custom
    severity_rules = _validate_severity_rules(transport, cfg.get("severity_rules"))
    if severity_rules:
        if any("priority" in r for r in severity_rules.values()) and transport not in (
            "jira",
            "servicenow",
        ):
            raise MappingError(
                f"severity_rules priority is only supported for jira and servicenow, not {transport}"
            )
        out["severity_rules"] = severity_rules
    target_rules = _validate_target_rules(transport, cfg.get("target_rules"), validate_target)
    if target_rules:
        out["target_rules"] = target_rules
    return out


# --------------------------------------------------------------------------
# Resolution for one event
# --------------------------------------------------------------------------


@dataclass
class Resolution:
    """What the mapping decided for one event."""

    create: bool = True
    priority: str | None = None
    labels: list[str] = field(default_factory=list)
    target: Any = None  # None = keep the base config's target
    skip_reason: str | None = None


def _rule_matches(rule: dict[str, Any], severity: str, asset: dict[str, Any]) -> bool:
    if rule.get("severities") and severity not in rule["severities"]:
        return False
    for key in ("business_unit", "environment"):
        if key in rule and str(asset.get(key) or "").strip().lower() != rule[key].lower():
            return False
    criticality = asset.get("criticality")
    for key, cmp in (("min_criticality", lambda c, v: c >= v), ("max_criticality", lambda c, v: c <= v)):
        if key in rule:
            # An asset with no criticality set cannot satisfy a bound on it.
            if not isinstance(criticality, int) or not cmp(criticality, rule[key]):
                return False
    return True


def resolve(cfg: dict[str, Any], severity: str, asset: dict[str, Any] | None) -> Resolution:
    """Apply ``severity_rules`` and the first matching ``target_rules`` entry."""
    asset = asset or {}
    res = Resolution(labels=list(cfg.get("labels") or []))
    rule = (cfg.get("severity_rules") or {}).get(severity)
    if rule:
        if not rule.get("create", True):
            res.create = False
            res.skip_reason = f"severity {severity} is configured not to open tickets"
            return res
        res.priority = rule.get("priority")
        res.labels += [x for x in rule.get("labels", []) if x not in res.labels]
    for target_rule in cfg.get("target_rules") or []:
        if _rule_matches(target_rule, severity, asset):
            res.target = target_rule["target"]
            res.labels += [x for x in target_rule.get("labels", []) if x not in res.labels]
            break
    return res


def needs_asset_context(cfg: dict[str, Any]) -> bool:
    """Whether a database lookup of the asset can change the outcome."""
    if cfg.get("target_rules"):
        return True
    texts = [cfg.get("summary_template"), cfg.get("description_template")]
    custom = cfg.get("custom_fields") or {}
    for value in custom.values():
        texts.extend(value if isinstance(value, list) else [value])
    asset_tokens = {"business_unit", "environment", "criticality", "owner"}
    return any(
        isinstance(t, str) and asset_tokens & set(_TOKEN.findall(t)) for t in texts if t
    )
