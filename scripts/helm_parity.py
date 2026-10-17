#!/usr/bin/env python3
"""Compare two rendered manifest streams: the kustomize base and the Helm chart.

    helm_parity.py <kustomize.yaml> <helm.yaml>
    helm_parity.py --sync <kustomize.yaml> <chart-dir>

`--sync` rewrites <chart-dir>/files from the kustomize render: the large ConfigMap
payloads (scanner config, ClickHouse and NATS config, the backup script) live there
as plain files so `.Files.Get` can load them, and this is how a change to the base
reaches them. The comparison below then proves nothing drifted.

Exit 0 when both streams hold the same objects (kind, namespace, name) and every
object is equal after normalisation, 1 otherwise, with a unified diff per object.

Not byte-for-byte: key order, comments and the generator that produced a file are
irrelevant, so the comparison is on parsed objects. What is normalised away, and
nothing else:

  * metadata.labels["app.kubernetes.io/managed-by"] (kustomize vs Helm) and the
    helm.sh/* labels and annotations;
  * Secret `data` is decoded, so the base's base64 and the chart's are compared
    as the values they carry (`stringData` is merged into it).

Everything else is compared in full, which includes what the hardening rests on:
securityContext, capabilities, readOnlyRootFilesystem, automountServiceAccountToken,
NetworkPolicy rules, probes, resources, volumes and images.
"""

from __future__ import annotations

import base64
import copy
import difflib
import os
import sys

import yaml

MANAGED_BY = "app.kubernetes.io/managed-by"


def _load(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [doc for doc in yaml.safe_load_all(fh) if doc]


def _key(obj: dict) -> tuple[str, str, str]:
    meta = obj.get("metadata", {})
    return obj.get("kind", ""), meta.get("namespace", ""), meta.get("name", "")


def _normalise(obj: dict) -> dict:
    obj = copy.deepcopy(obj)
    meta = obj.setdefault("metadata", {})
    for field in ("labels", "annotations"):
        values = meta.get(field)
        if not values:
            meta.pop(field, None)
            continue
        values.pop(MANAGED_BY, None)
        for name in [n for n in values if n.startswith("helm.sh/")]:
            del values[name]
        if not values:
            del meta[field]
    if obj.get("kind") == "Secret":
        merged = {k: base64.b64decode(v).decode() for k, v in (obj.pop("data", None) or {}).items()}
        merged.update(obj.pop("stringData", None) or {})
        obj["data"] = merged
    return obj


def _dump(obj: dict) -> list[str]:
    return yaml.safe_dump(obj, sort_keys=True, default_flow_style=False).splitlines()


def _index(path: str, side: str) -> tuple[dict, int]:
    """Objects by (kind, namespace, name); a repeated identity is a failure, not a merge."""
    objects: dict = {}
    duplicates = 0
    for obj in _load(path):
        key = _key(obj)
        if key in objects:
            print("DUPLICATE in %s: %s %s/%s" % (side, key[0], key[1] or "-", key[2]))
            duplicates += 1
        objects[key] = _normalise(obj)
    return objects, duplicates


def compare(kustomize_path: str, helm_path: str) -> int:
    left, dup_left = _index(kustomize_path, "kustomize")
    right, dup_right = _index(helm_path, "chart")
    failures = dup_left + dup_right

    for key in sorted(left.keys() - right.keys()):
        print("MISSING in chart: %s %s/%s" % (key[0], key[1] or "-", key[2]))
        failures += 1
    for key in sorted(right.keys() - left.keys()):
        print("EXTRA in chart:   %s %s/%s" % (key[0], key[1] or "-", key[2]))
        failures += 1
    for key in sorted(left.keys() & right.keys()):
        if left[key] == right[key]:
            continue
        failures += 1
        print("DIFFERS: %s %s/%s" % (key[0], key[1] or "-", key[2]))
        for line in difflib.unified_diff(
            _dump(left[key]), _dump(right[key]), "kustomize", "helm", lineterm="", n=2
        ):
            print("  " + line)

    print(
        "objects: kustomize=%d helm=%d, differing=%d"
        % (len(left), len(right), failures)
    )
    return 1 if failures else 0


# ConfigMap name -> directory under files/. Mirrors templates/configmaps.yaml;
# the parity run fails if the two ever disagree.
_FILE_BACKED = {
    "scanner-config": "scanner-config",
    "shapoclyack-clickhouse-backup-script": "clickhouse-backup",
    "shapoclyack-clickhouse-config": "clickhouse",
    "shapoclyack-nats-config": "nats",
}


def sync(kustomize_path: str, chart_dir: str) -> int:
    written = 0
    wanted: dict[str, set[str]] = {}
    for obj in _load(kustomize_path):
        meta = obj.get("metadata", {})
        if obj.get("kind") != "ConfigMap":
            continue
        # The executor namespace's copy of scanner-config is the same file.
        if meta.get("namespace") != "network-scan":
            continue
        subdir = _FILE_BACKED.get(meta["name"])
        if subdir is None:
            print(
                "WARNING: base ConfigMap %s is not carried by the chart; add it to "
                "_FILE_BACKED here and to templates/configmaps.yaml" % meta["name"],
                file=sys.stderr,
            )
            continue
        target = os.path.join(chart_dir, "files", subdir)
        os.makedirs(target, exist_ok=True)
        wanted[subdir] = set(obj.get("data", {}))
        for name, text in obj.get("data", {}).items():
            with open(os.path.join(target, name), "w", encoding="utf-8") as fh:
                fh.write(text)
            written += 1
    removed = 0
    for subdir, names in wanted.items():
        target = os.path.join(chart_dir, "files", subdir)
        for name in sorted(set(os.listdir(target)) - names):
            os.remove(os.path.join(target, name))
            print("removed stale %s/%s" % (subdir, name))
            removed += 1
    print("synced %d file(s) into %s/files, removed %d stale" % (written, chart_dir, removed))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--sync":
        sys.exit(sync(sys.argv[2], sys.argv[3]))
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(compare(sys.argv[1], sys.argv[2]))
