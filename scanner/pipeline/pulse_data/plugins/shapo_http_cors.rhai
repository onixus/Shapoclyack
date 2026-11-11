// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One GET with an Origin header; report a wildcard CORS allow with credentials.
fn name() { "shapo_http_cors" }
fn description() { "Detect permissive CORS headers on plain HTTP." }
fn ports() { [] }
fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}
fn run() {
    let greeting = banner.to_lower();
    if !(service == "http" || greeting.starts_with("http/")) { return; }
    let reply = probe_send(port, "GET / HTTP/1.1\r\nHost: shapoclyack.invalid\r\nOrigin: http://shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    if reply.len() == 0 { return; }
    let lines = reply.split("\n");
    let status = "";
    if lines.len() > 0 {
        status = lines[0];
        status.trim();
    }
    if !status.starts_with("HTTP/") { throw "no HTTP status line in the reply: " + head(reply, 60); }
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
        if alt < 0 { throw "no end of HTTP headers in the reply"; }
        header_block = reply.sub_string(0, alt);
    }
    let allow_origin = "";
    let allow_creds = "";
    for line in header_block.split("\n") {
        let l = line;
        l.trim();
        let lower = l.to_lower();
        if lower.starts_with("access-control-allow-origin:") {
            let raw = l.sub_string(28);
            raw.trim();
            allow_origin = raw;
        }
        if lower.starts_with("access-control-allow-credentials:") {
            let raw = l.sub_string(33);
            raw.trim();
            allow_creds = raw;
        }
    }
    if allow_origin != "*" { return; }
    if allow_creds.to_lower() != "true" { return; }
    return #{
        title: "HTTP CORS allows any origin with credentials",
        severity: "LOW",
        summary: "The response carries Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true on plain HTTP. Other CORS combinations are not reported.",
        evidence: "Wildcard CORS allow with credentials observed."
    };
}
