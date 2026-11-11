// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One OPTIONS request; report if the Allow header lists PUT, DELETE or CONNECT.
// TRACE is handled by shapo_http_trace. Only plain HTTP is checked.
fn name() { "shapo_http_methods" }
fn description() { "Detect dangerous HTTP methods advertised in the Allow header." }
fn ports() { [] }
fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}
fn run() {
    let greeting = banner.to_lower();
    if !(service == "http" || greeting.starts_with("http/")) { return; }
    let reply = probe_send(port, "OPTIONS / HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    if reply.len() == 0 { return; }
    let lines = reply.split("\n");
    let status = "";
    if lines.len() > 0 {
        status = lines[0];
        status.trim();
    }
    if !status.starts_with("HTTP/") { throw "no HTTP status line in the OPTIONS reply: " + head(reply, 60); }
    let parts = status.split(" ");
    if parts.len() < 2 || parts[1].len() != 3 { throw "malformed HTTP status line: " + head(status, 60); }
    let code = parts[1];
    if code == "401" || code == "403" { return; }
    if code == "301" || code == "302" || code == "303" || code == "307" || code == "308" { return; }
    let sep = reply.index_of("\r\n\r\n");
    let header_block = "";
    if sep >= 0 {
        header_block = reply.sub_string(0, sep);
    } else {
        let alt = reply.index_of("\n\n");
        if alt < 0 { throw "no end of HTTP headers in the OPTIONS reply"; }
        header_block = reply.sub_string(0, alt);
    }
    let allow = "";
    for line in header_block.split("\n") {
        let l = line;
        l.trim();
        let lower = l.to_lower();
        if lower.starts_with("allow:") {
            let raw = l.sub_string(6);
            raw.trim();
            allow = raw;
        }
    }
    if allow.len() == 0 { return; }
    let dangerous = false;
    for token in allow.split(",") {
        let t = token;
        t.trim();
        t = t.to_lower();
        if t == "put" || t == "delete" || t == "connect" { dangerous = true; }
    }
    if !dangerous { return; }
    return #{
        title: "HTTP server advertises dangerous methods",
        severity: "LOW",
        summary: "The OPTIONS response lists PUT, DELETE or CONNECT in the Allow header. This does not prove the methods are usable on every resource; only that the server reports them as allowed.",
        evidence: "Allow header contains a dangerous method: " + head(allow, 80)
    };
}
