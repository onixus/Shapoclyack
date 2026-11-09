// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One plain-HTTP GET of /api/whoami with no Authorization header; the guest
// account is not substituted. The finding is a 200 JSON document carrying
// both the name and tags members. A 401/403 or a redirect is how a broker
// normally answers. Queues, users and the aliveness test are not requested;
// nothing is declared or written.
fn name() { "shapo_rabbitmq_mgmt" }
fn description() { "Detect RabbitMQ management whoami endpoints answering without authentication." }
fn ports() { [] }
fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}
fn decode_chunked(body) {
    let out = "";
    let rest = body;
    for guard in 0..64 {
        if rest.len() == 0 { throw "truncated chunked body"; }
        let eol = rest.index_of("\r\n");
        if eol < 1 { throw "bad chunk size line"; }
        let size_line = rest.sub_string(0, eol);
        let semi = size_line.index_of(";");
        let size_text = if semi >= 0 { size_line.sub_string(0, semi) } else { size_line };
        let digits = "0123456789abcdef";
        let n = 0;
        let i = 0;
        while i < size_text.len() {
            let d = digits.index_of(size_text.sub_string(i, 1).to_lower());
            if d < 0 { throw "bad chunk size digit"; }
            n = n * 16 + d;
            i += 1;
        }
        if size_text.len() == 0 || n > 65536 { throw "bad chunk size"; }
        if n == 0 {
            let tail = rest.sub_string(eol + 2);
            if tail.len() == 0 || tail == "\r\n" { return out; }
            if tail.ends_with("\r\n\r\n") { return out; }
            throw "bad chunk trailer";
        }
        let data_at = eol + 2;
        if data_at + n + 2 > rest.len() { throw "truncated chunk data"; }
        out += rest.sub_string(data_at, n);
        if rest.sub_string(data_at + n, 2) != "\r\n" { throw "bad chunk delimiter"; }
        rest = rest.sub_string(data_at + n + 2);
    }
    throw "too many chunks";
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "rabbitmq-mgmt" || (unnamed && port == 15672)) { return; }
    let reply = probe_send(port, "GET /api/whoami HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    if reply.len() == 0 { throw "empty whoami endpoint reply"; }
    let lines = reply.split("\n");
    let status = lines[0];
    status.trim();
    if !status.starts_with("HTTP/") { throw "no HTTP status line in the whoami reply: " + head(reply, 60); }
    let parts = status.split(" ");
    if parts.len() < 2 || parts[1].len() != 3 { throw "malformed HTTP status line in the whoami reply: " + head(status, 60); }
    let code = parts[1];
    let sep = reply.index_of("\r\n\r\n");
    let header_block = "";
    let body = "";
    if sep >= 0 {
        header_block = reply.sub_string(0, sep);
        body = reply.sub_string(sep + 4);
    } else {
        let alt = reply.index_of("\n\n");
        if alt < 0 { throw "no end of HTTP headers in the whoami reply"; }
        header_block = reply.sub_string(0, alt);
        body = reply.sub_string(alt + 2);
    }
    let content_length = -1;
    let chunked = false;
    for line in header_block.split("\n") {
        let l = line;
        l.trim();
        l = l.to_lower();
        if l.starts_with("transfer-encoding:") && l.contains("chunked") { chunked = true; }
        if l.starts_with("content-length:") {
            let raw = l.sub_string(15);
            raw.trim();
            if raw.len() < 1 || raw.len() > 8 { throw "invalid Content-Length in the whoami reply"; }
            content_length = parse_int(raw);
        }
    }
    if chunked {
        body = decode_chunked(body);
    } else if content_length >= 0 && body.len() != content_length {
        throw "truncated whoami reply body: " + body.len() + " of " + content_length + " bytes";
    }
    if code == "401" || code == "403" { return; }
    if code == "301" || code == "302" || code == "303" || code == "307" || code == "308" { return; }
    if code != "200" { throw "unexpected HTTP status from the whoami endpoint: " + head(status, 60); }
    if !json_object(body) { throw "whoami reply is not one complete JSON object"; }
    let flat = json_flat(body);
    if !(flat.contains("\"name\":") && flat.contains("\"tags\":")) { throw "whoami JSON has no name and tags members"; }
    return #{
        title: "RabbitMQ management whoami answered without authentication",
        severity: "LOW",
        summary: "The whoami document was read with no Authorization header and no guest credentials. User, queue and overview listings were not requested and nothing was written or logged into.",
        evidence: "The whoami endpoint returned a complete JSON document without an Authorization header."
    };
}
// The body with JSON insignificant whitespace removed, for exact member
// markers. Spaces inside string values collapse too; values are never
// inspected, only markers.
fn json_flat(body) {
    let flat = body;
    flat.replace("\r", "");
    flat.replace("\n", "");
    flat.replace("\t", "");
    flat.replace(" ", "");
    flat
}
// The trimmed body is exactly one JSON object: it opens and closes with
// braces, so a reply cut mid-document does not slip through.
fn json_object(body) {
    let t = body;
    t.trim();
    t.len() >= 2 && t.starts_with("{") && t.ends_with("}")
}
