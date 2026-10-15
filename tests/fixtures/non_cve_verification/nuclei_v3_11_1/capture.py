import http.server
import threading
import pathlib
import json
import subprocess
from scanner.pipeline.nuclei_scan import run_nuclei_scan
from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.non_cve_verification import target_subject

root = pathlib.Path("/evidence")
templates = root / "templates"
templates.mkdir(exist_ok=True)
url = "http://127.0.0.1:18088/backup.zip"
state = {"exposed": True}
requests = []


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        requests.append(self.path)
        body = (
            b"EXPOSED_SECRET"
            if state["exposed"] and self.path == "/backup.zip"
            else b"clean"
        )
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 18088), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
content = """id: exposed-config
info:
  name: Local exact object fixture
  author: local
  severity: high
  tags: misconfig
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: word
        words: ["EXPOSED_SECRET"]
"""
rule = templates / "rule.yaml"
rule.write_text(content)
target = {"url": url, "subject": target_subject(url), "template_id": "exposed-config"}
config = NucleiConfig(
    templates_dir=str(templates),
    template_ids=["exposed-config"],
    verification_targets=[target],
    network_templates=False,
    http_ports=[18088],
    https_ports=[],
    non_cve_rules={
        "exposed-config": {
            "rule_id": "backup-exposure-v1",
            "issue_type": "misconfiguration",
            "remediation": "Remove the backup file.",
        }
    },
)
results = {}
for phase in ["positive", "remediated", "appended-path"]:
    if phase == "remediated":
        state["exposed"] = False
    if phase == "appended-path":
        state["exposed"] = True
        rule.write_text(content.replace("{{BaseURL}}", "{{BaseURL}}/backup.zip"))
    out = root / phase
    out.mkdir(exist_ok=True)
    before = len(requests)
    result = run_nuclei_scan(["127.0.0.1:18088/tcp"], config, out)
    results[phase] = {
        "requests": requests[before:],
        "findings": len(result.get("findings", [])),
        "actionable": len(result.get("actionable_findings", [])),
        "coverage": result["coverage"],
        "skipped_reason": result.get("skipped_reason"),
    }
results["version"] = subprocess.run(
    ["nuclei", "-version"], capture_output=True, text=True
).stderr
(root / "results.json").write_text(json.dumps(results, indent=2))
print(
    json.dumps(
        {
            phase: {key: value for key, value in data.items() if key != "coverage"}
            if isinstance(data, dict)
            else data
            for phase, data in results.items()
        }
    )
)
assert results["positive"]["requests"] == ["/backup.zip"]
assert results["positive"]["findings"] == 1
assert results["remediated"]["findings"] == 0
assert results["remediated"]["coverage"]["verification_targets"][0]["complete"] is True
assert not results["appended-path"]["requests"]
assert (
    results["appended-path"]["skipped_reason"]
    == "verification_template_exact_input_unproven"
)
server.shutdown()
