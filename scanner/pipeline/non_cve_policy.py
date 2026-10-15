"""Separate reviewed actionable identity from display classification.

Legacy scan rows can display type=exposure without joining the new identity
namespace. Only the scanner's explicit inclusion receipt opts an observation in.
"""
from typing import Any

POLICY = "nuclei-actionable-v1"


def actionable(row: dict[str, Any]) -> bool:
    return (not row.get("cve") and row.get("non_cve_policy") == POLICY
            and row.get("source") == "nuclei"
            and row.get("finding_type") in {"misconfiguration", "exposure"}
            and isinstance(row.get("rule_id"), str) and bool(row["rule_id"].strip())
            and isinstance(row.get("template_id"), str) and bool(row["template_id"].strip()))
