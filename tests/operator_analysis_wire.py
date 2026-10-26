"""Adapt historical supplied-output contract fixtures; never used by production.

The immutable legacy fixture contains full source tuples. Exact registered
tuples become local integer refs. Forged tuples retain their forbidden fields
and must still fail the new wire contract; no label or other field is repaired.
"""
from copy import deepcopy


def compact_fixture_output(output, retrieval):
    result = deepcopy(output)
    eligible = [item for item in retrieval["items"] if item["citation"]["status"] != "stale"]
    for selection in result.get("recommendations", []):
        fields = ("source_id", "source_hash", "snapshot_id")
        matches = [i for i, item in enumerate(eligible)
                   if all(selection.get(field) == item.get(field) for field in fields)]
        if len(matches) == 1:
            for field in fields:
                del selection[field]
            selection["source_ref"] = matches[0]
    return result
