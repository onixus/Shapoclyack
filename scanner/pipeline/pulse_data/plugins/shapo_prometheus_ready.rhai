// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Read the Prometheus build-info status over plain HTTP and report it when the
// endpoint answers an anonymous caller. One request, and the request asks the
// server to close the connection, so the reply is read to EOF. Plain HTTP
// only: the sandbox has no TLS, so TLS-only listeners are never reached.
//
// Confirmed: one complete JSON document with the success status member came
// back without credentials. Not checked: metrics, label values, PromQL, and
// any write or configuration access.
//
// Verdicts: 401/403 is a silent clean return (credentials are wanted). A
// reply that is not one complete HTTP document -- no status line, headers cut
// off, a chunked body, a Content-Length that disagrees with the bytes read to
// EOF, a body that is not one complete JSON object, a 200 without the success
// member, or any unexpected non-401/403 status -- raises an error: "not
// exposed" cannot be claimed from an answer that was not understood. The JSON
// check is structural (header terminator, length, outer braces, flattened
// member markers), not a full parser; evidence carries no body, no version
// and no label values.
fn name() { "shapo_prometheus_ready" }
fn description() { "Report a Prometheus build-info status readable without authentication." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "prometheus" || (unnamed && port == 9090)) { return; }
    let reply = probe_send(port, "GET /api/v1/status/buildinfo HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    let parts = http_read(reply);
    let code = parts[0];
    let body = parts[2];
    if code == 401 || code == 403 { return; }
    if code != 200 { throw "unexpected HTTP status " + code + " from the build-info endpoint"; }
    if !json_object(body) { throw "build-info reply is not one complete JSON object"; }
    if !json_flat(body).contains("\"status\":\"success\"") { throw "build-info JSON has no success status member"; }
    return #{
        title: "Prometheus build info readable without authentication",
        severity: "LOW",
        summary: "The build-info document was read without credentials. Metrics, label values and PromQL were not requested; write access is not implied.",
        evidence: "The build-info endpoint returned a complete JSON success document without authentication."
    };
}

// --- HTTP helpers (one reply, read to EOF) ---------------------------------

// [status_code, headers_block, body]. Raises when the reply is not one
// complete-enough HTTP reply: a bad status line, headers cut off, a chunked
// body, or a Content-Length that disagrees with the body read to EOF.
fn http_read(reply) {
    if reply.len() < 8 || !reply.starts_with("HTTP/") {
        throw "reply is not HTTP";
    }
    let nl = reply.index_of("\n");
    if nl < 0 {
        throw "HTTP reply is cut off inside the status line";
    }
    let line = reply.sub_string(0, nl).trim();
    let sp = line.index_of(" ");
    if sp < 0 {
        throw "malformed HTTP status line";
    }
    let pos = sp + 1;
    while pos < line.len() && line.sub_string(pos, 1) == " " {
        pos += 1;
    }
    if pos + 3 > line.len() {
        throw "malformed HTTP status line";
    }
    let token = line.sub_string(pos, 3);
    let digits = "0123456789";
    if !(digits.contains(token.sub_string(0, 1)) && digits.contains(token.sub_string(1, 1)) && digits.contains(token.sub_string(2, 1))) {
        throw "malformed HTTP status code";
    }
    let code = parse_int(token);
    let sep = reply.index_of("\r\n\r\n");
    let sep_len = 4;
    if sep < 0 {
        sep = reply.index_of("\n\n");
        sep_len = 2;
    }
    if sep < 0 {
        throw "HTTP reply is cut off inside the headers";
    }
    let head = "";
    if sep > nl {
        head = reply.sub_string(nl + 1, sep - nl - 1);
    }
    let body = reply.sub_string(sep + sep_len, reply.len() - sep - sep_len);
    let lower = head.to_lower();
    if lower.contains("transfer-encoding:") && lower.contains("chunked") {
        throw "chunked HTTP reply is not parsed";
    }
    let wanted = -1;
    for hline in head.split("\n") {
        let t = hline.trim().to_lower();
        if t.starts_with("content-length:") {
            let v = t.sub_string(15, t.len() - 15).trim();
            let n = 0;
            try {
                n = parse_int(v);
            } catch (e) {
                throw "malformed Content-Length header";
            }
            if n < 0 {
                throw "negative Content-Length header";
            }
            wanted = n;
        }
    }
    if wanted >= 0 && body.len() != wanted {
        throw "HTTP body length does not match Content-Length";
    }
    [code, head, body]
}

// The body with JSON insignificant whitespace removed, for exact member
// markers. Spaces inside string values collapse too; values are never
// inspected, only markers.
fn json_flat(body) {
    body.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "")
}

// The trimmed body is exactly one JSON object: it opens and closes with
// braces, so a reply cut mid-document does not slip through.
fn json_object(body) {
    let t = body.trim();
    t.len() >= 2 && t.starts_with("{") && t.ends_with("}")
}
