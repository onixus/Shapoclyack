"""Typed parser outputs for controlled unit fixtures, never a model-quality claim."""
import json


def intent_wire(intent, subject_kind=None, *, selector=None, mentions=None):
    defaults = {"summarize_run": "run", "analyze_run": "run", "compare_runs": "run",
                "find_remediation": "device", "cancel_scan": "job", "verify_finding": "finding",
                "prepare_scan": "scan_scope", "abstain": "unspecified"}
    return json.dumps({"intent": intent, "subject_kind": subject_kind or defaults[intent],
                      "selector": selector or ("none" if intent == "abstain" else "contextual"),
                      "mentions": mentions or []})
