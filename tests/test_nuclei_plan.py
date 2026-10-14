"""Planner policy regressions; no external target is contacted."""

import json
import subprocess
from pathlib import Path

from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.nuclei_plan import build_plan, catalog
from scanner.pipeline.nuclei_scan import run_nuclei_scan


def template(root, name="fixture-cve", tags="cve", protocol="http"):
    root.mkdir(exist_ok=True)
    (root / f"{name}.yaml").write_text(
        f"id: {name}\ninfo:\n  name: fixture\n  author: tests\n  severity: high\n  tags: {tags}\n{protocol}:\n  - method: GET\n    path: ['{{{{BaseURL}}}}/']\n"
    )


def test_catalog_content_identity_custom_policy_and_bounds(tmp_path):
    base, custom = tmp_path / "base", tmp_path / "custom"
    template(base)
    template(custom, "custom", tags="custom")
    digest, rows, error = catalog([base, custom], 10)
    assert error is None and {r["origin"] for r in rows} == {"pinned", "custom"}
    assert catalog([base, custom], 10)[1] is rows
    template(custom, "unsafe", tags="dos")
    changed, rows2, error = catalog([base, custom], 10)
    assert changed != digest and error is None
    plan = build_plan(["10.0.0.1:80/tcp"], [], NucleiConfig(), changed, rows2)
    assert plan["template_sets"]["safe_http_fallback"] == ["custom", "fixture-cve"]
    assert catalog([base, custom], 1)[2] == "catalog_limit"
    template(custom, "fixture-cve")
    assert catalog([base, custom], 10)[2] == "catalog_ambiguous_id"


def test_known_unknown_conflicting_nonstandard_ipv6_and_vhosts(tmp_path):
    template(tmp_path)
    digest, rows, _ = catalog([tmp_path], 10)
    cfg = NucleiConfig(planner_mode="directed")
    scope = ["[2001:db8::1]:9443/tcp", "10.0.0.1:1234/tcp", "10.0.0.2:80/udp"]
    services = [
        {"ip": "2001:db8::1", "port": 9443, "service": "https", "confidence": 95},
        {"ip": "10.0.0.9", "port": 80, "service": "http", "confidence": 100},
    ]
    names = {"2001:db8::1": ["b.example", "a.example"]}
    plan = build_plan(scope, services, cfg, digest, rows, names)
    assert len(plan["targets"]) == 5
    tls = [t for t in plan["targets"] if t["port"] == 9443]
    assert all(t["url"] == "https://[2001:db8::1]:9443/" for t in tls)
    assert {t["sni"] for t in tls} == {None, "a.example", "b.example"}
    assert plan == build_plan(
        list(reversed(scope)), list(reversed(services)), cfg, digest, rows, names
    )
    services.append(
        {"ip": "2001:db8::1", "port": 9443, "service": "http", "confidence": 95}
    )
    wrong = build_plan(scope, services, cfg, digest, rows, names)
    assert {t["url"].split(":")[0] for t in wrong["targets"] if t["port"] == 9443} == {
        "http",
        "https",
    }
    assert all(t["ip"] != "10.0.0.9" for t in wrong["targets"])


def test_version_hint_never_removes_cve_and_caps_without_cartesian_artifact(tmp_path):
    template(tmp_path)
    template(tmp_path, "other-cve", tags="apache,cve")
    digest, rows, _ = catalog([tmp_path], 10)
    cfg = NucleiConfig(max_targets=1)
    plan = build_plan(
        ["10.0.0.1:8001/tcp"],
        [{"ip": "10.0.0.1", "port": 8001, "product": "nginx", "version": "1.0"}],
        cfg,
        digest,
        rows,
    )
    assert plan["template_sets"]["safe_http_fallback"] == ["fixture-cve", "other-cve"]
    assert plan["skipped"] == [{"reason": "max_targets", "count": 1}]
    assert plan["executed_checks"] is None and not plan["complete"]
    assert len(plan["catalog"]) == 2 and len(plan["targets"]) == 1


def test_timeout_keeps_jsonl_without_checked_coverage(tmp_path, monkeypatch):
    template(tmp_path / "templates")
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", lambda _: "nuclei")
    raw = {
        "template-id": "fixture-cve",
        "host": "10.0.0.1",
        "port": "80",
        "info": {"severity": "high"},
    }

    def run(cmd, **kw):
        Path(cmd[cmd.index("-jsonl-export") + 1]).write_text(
            json.dumps(raw) + "\n{partial"
        )
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", run)
    result = run_nuclei_scan(
        ["10.0.0.1:80/tcp"],
        NucleiConfig(
            templates_dir=str(tmp_path / "templates"), network_templates=False
        ),
        tmp_path,
    )
    assert result["findings"][0]["template_id"] == "fixture-cve"
    assert not result["coverage"]["ran"] and result["checked_count"] == 0


def test_runtime_directed_targets_headers_budget_and_loaded_count(
    tmp_path, monkeypatch
):
    template(tmp_path / "templates")
    (tmp_path / "services.json").write_text(
        json.dumps(
            [{"ip": "10.0.0.1", "port": 1234, "service": "https", "confidence": 100}]
        )
    )
    (tmp_path / "dns_resolution.json").write_text(
        json.dumps(
            {
                "records": [
                    {"host": "a.example", "a": ["10.0.0.1"]},
                    {"host": "b.example", "a": ["10.0.0.1"]},
                ]
            }
        )
    )
    seen = []

    def run(cmd, **kw):
        seen.append((cmd, kw, Path(cmd[cmd.index("-list") + 1]).read_text()))
        Path(cmd[cmd.index("-jsonl-export") + 1]).write_text("")
        return subprocess.CompletedProcess(
            cmd, 0, "", "[INF] Templates loaded for current scan: 1"
        )

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", lambda _: "nuclei")
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", run)
    result = run_nuclei_scan(
        ["10.0.0.1:1234/tcp"],
        NucleiConfig(
            planner_mode="directed",
            templates_dir=str(tmp_path / "templates"),
            network_templates=False,
        ),
        tmp_path,
    )
    assert len(seen) == 3
    assert all(
        "-disable-redirects" in c and k["retries"] == 0 and k["timeout"] <= 1800
        for c, k, _ in seen
    )
    assert {c[c.index("-sni") + 1] for c, _, _ in seen if "-sni" in c} == {
        "a.example",
        "b.example",
    }
    assert all(u == "https://10.0.0.1:1234/\n" for _, _, u in seen)
    assert result["coverage"]["plan"]["complete"] and result["checked_count"] == 3
    assert result["coverage"]["plan"]["executed_checks"] is None
