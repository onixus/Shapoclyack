"""Reports preserve actionable non-CVE identity and safely render remediation."""
from api.services.reports import content, render


def test_report_body_and_renderers_distinguish_cve_and_non_cve(monkeypatch):
    row = {"cve": None, "title": "Public backup", "finding_type": "misconfiguration",
           "detector_source": "nuclei", "template_id": "public-backup",
           "remediation": "Remove <script>alert(1)</script> from the web root.",
           "finding_evidence": {"observation_count": 2}, "state": "OPEN"}
    monkeypatch.setattr(content.branding_service, "get_branding", lambda *a, **k: {})
    monkeypatch.setattr(content.vulns_service, "summary", lambda *a, **k: {
        "total": 3, "open_total": 2, "cve_findings": 1, "non_cve_findings": 2})
    monkeypatch.setattr(content.vulns_service, "list_vulnerabilities", lambda *a, **k: ([row], 1))
    body = content.build(None, tenant_id="tenant-a", kind="technical",
                         sections={name: name in {"kpis", "top_findings"} for name in content.SECTIONS})
    assert body["kpis"]["cve_findings"] == 1
    assert body["kpis"]["non_cve_findings"] == 2
    finding = body["top_findings"][0]
    for key in ["cve", "finding_type", "detector_source", "template_id", "remediation", "finding_evidence"]:
        assert finding[key] == row[key]
    page = render.render_html(body)
    assert "Non-CVE findings (all states)" in page
    assert "misconfiguration" in page and "nuclei" in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<script>alert(1)</script>" not in page
    assert render.render_pdf(body).startswith(b"%PDF")


def test_old_report_snapshots_do_not_claim_zero_cve_counts():
    body = {"title": "Historic report", "sections": ["kpis"],
            "kpis": {"total": 12, "open_total": 12}}
    assert "CVE findings (all states)" not in render.render_html(body)
    assert render.render_pdf(body).startswith(b"%PDF")
