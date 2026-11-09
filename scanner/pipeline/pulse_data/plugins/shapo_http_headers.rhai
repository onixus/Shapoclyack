// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Confirms: one anonymous header-only request against a plain-HTTP reply
// that serves content comes back without content-type sniffing protection
// and without framing protection. Not checked: a second request over TLS,
// HSTS (its absence on plain HTTP is not a finding), the quality of any CSP.
fn name() { "shapo_http_headers" }
fn description() { "Report plain-HTTP content responses missing content-type and framing protection headers." }
fn ports() { [] }
fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}
fn run() {
    let greeting = banner.to_lower();
    if !(service == "http" || greeting.starts_with("http/")) { return; }
    let reply = probe_send(port, "HEAD / HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    if reply.len() == 0 { throw "empty reply to the header check"; }
    let lines = reply.split("\n");
    let status = "";
    if lines.len() > 0 { status = lines[0].trim(); }
    if !status.starts_with("HTTP/") { throw "header check reply is not HTTP: " + head(reply, 60); }
    let parts = status.split(" ");
    if parts.len() < 2 || parts[1].len() != 3 { throw "unparseable HTTP status line: " + head(status, 60); }
    let code = parts[1];
    let serves = code == "200" || code == "301" || code == "302" || code == "303" || code == "307" || code == "308";
    if !serves { return; }
    let sep4 = reply.index_of("\r\n\r\n");
    let sep2 = reply.index_of("\n\n");
    let block = reply;
    if sep4 >= 0 { block = reply.sub_string(0, sep4); }
    else if sep2 >= 0 { block = reply.sub_string(0, sep2); }
    let text = block.to_lower();
    let has_nosniff = text.contains("x-content-type-options:");
    let has_framing = text.contains("x-frame-options:") || text.contains("content-security-policy:");
    if has_nosniff || has_framing { return; }
    return #{
        title: "Plain-HTTP response misses content-type and framing protection headers",
        severity: "LOW",
        summary: "The reply carries neither X-Content-Type-Options nor X-Frame-Options/Content-Security-Policy. A second request over TLS and the quality of any CSP were not checked.",
        evidence: code + " reply carried neither X-Content-Type-Options nor X-Frame-Options nor Content-Security-Policy."
    };
}
