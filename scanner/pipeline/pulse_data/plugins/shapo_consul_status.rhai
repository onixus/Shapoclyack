// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Read the Consul leader status over plain HTTP and report it when the
// endpoint answers an anonymous caller. One request, and the request asks the
// server to close the connection, so the reply is read to EOF. Plain HTTP
// only: the sandbox has no TLS, so TLS-only listeners are never reached.
//
// Confirmed: the leader status endpoint returned one complete quoted string
// without credentials. The address contents are never recorded. Not checked:
// KV data, the catalog and ACL tokens. An empty answer to a refused request
// (401/403) is a clean return, not an error.
//
// Verdicts: 401/403 is a silent clean return, with or without a body
// (credentials are wanted). A reply that is not one complete HTTP document --
// no status line, headers cut off, a chunked body, a Content-Length that
// disagrees with the bytes read to EOF, a body that is not exactly one
// complete JSON string, or any unexpected non-401/403 status -- raises an
// error: "not exposed" cannot be claimed from an answer that was not
// understood. The JSON check is structural (header terminator, length, the
// opening and closing quote), not a full parser; evidence carries no body
// and no address.
fn name() { "shapo_consul_status" }
fn description() { "Report a Consul leader status string readable without authentication." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "consul" || (unnamed && port == 8500)) { return; }
    let reply = probe_send(port, "GET /v1/status/leader HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    let parts = http_read(reply);
    let code = parts[0];
    let body = parts[2];
    if code == 401 || code == 403 { return; }
    if code != 200 { throw "unexpected HTTP status " + code + " from the leader status endpoint"; }
    if !json_string(body) { throw "leader status reply is not one complete JSON string"; }
    return #{
        title: "Consul leader status readable without authentication",
        severity: "LOW",
        summary: "The leader status string was read without credentials. KV data, the catalog and ACL tokens were not requested.",
        evidence: "The leader status endpoint returned one complete quoted string without authentication; its contents are not recorded."
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

// The trimmed body is exactly one JSON string: it opens and closes with a
// quote, so a reply cut mid-string does not slip through. The contents are
// never copied anywhere.
fn json_string(body) {
    let t = body.trim();
    if t.len() < 2 || !t.starts_with("\"") || !t.ends_with("\"") { return false; }
    let escaped = false;
    let i = 1;
    while i < t.len() - 1 {
        let ch = t.sub_string(i, 1);
        if ch == "\"" && !escaped { return false; }
        if ch == "\\" && !escaped { escaped = true; } else { escaped = false; }
        i += 1;
    }
    return !escaped;
}
