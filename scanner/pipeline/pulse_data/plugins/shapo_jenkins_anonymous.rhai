// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Ask Jenkins who the anonymous caller is and report when the answer comes
// back without authentication: either the product header or a complete
// anonymous-user JSON document on that endpoint. One request, and the request
// asks the server to close the connection, so the reply is read to EOF.
// Plain HTTP only: the sandbox has no TLS, so TLS-only listeners are never
// reached.
//
// The product header on a 403 is not a finding: that is the probe recognising
// the product, not the status API serving an anonymous caller. Confirmed: the
// whoAmI answer identified an anonymous session without credentials. Not
// checked: login, job execution and the script console.
//
// Verdicts: 401/403, and any other complete HTTP answer that carries neither
// the product header nor the anonymous-user document, is a silent clean
// return -- the phase item treats only a non-HTTP answer as an error. A
// reply that is not one complete HTTP document (a bad status line, headers
// cut off, a chunked body, or a Content-Length that disagrees with the bytes
// read to EOF) raises an error. Evidence carries no user name and no body.
fn name() { "shapo_jenkins_anonymous" }
fn description() { "Report a Jenkins whoAmI answer served to an anonymous caller." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "jenkins" || (unnamed && port == 8080) || (unnamed && port == 8088)) { return; }
    let reply = probe_send(port, "GET /whoAmI/api/json HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    let parts = http_read(reply);
    let code = parts[0];
    let head = parts[1];
    let body = parts[2];
    if code == 401 || code == 403 { return; }
    if code != 200 { return; }
    let jenkins_signs = head.to_lower().contains("x-jenkins:");
    if !jenkins_signs && json_object(body) {
        jenkins_signs = json_flat(body).contains("\"anonymous\":true");
    }
    if !jenkins_signs { return; }
    return #{
        title: "Jenkins whoAmI readable without authentication",
        severity: "LOW",
        summary: "The whoAmI endpoint returned 200 with a Jenkins product header or an anonymous identity document. Login, job execution and the script console were not attempted.",
        evidence: "The whoAmI endpoint answered the anonymous request with the product header or an anonymous-user document."
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
