// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One GET with a fixed NTLM Type1; report a well-formed Type2 challenge.
// No Type3, credentials or domain-credential validation is attempted.
fn name() { "shapo_http_ntlm_info" }
fn description() { "Detect an NTLM Type2 challenge returned over plain HTTP." }
fn ports() { [] }
fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}
fn is_base64(text) {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let i = 0;
    while i < text.len() {
        let ch = text.sub_string(i, 1);
        if ch != "=" && alphabet.index_of(ch) < 0 { return false; }
        i += 1;
    }
    return true;
}
fn run() {
    let greeting = banner.to_lower();
    if !(service == "http" || greeting.starts_with("http/")) { return; }
    // Fixed NTLM Type1 with no workstation/domain (40 raw bytes).
    let type1 = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA";
    let reply = probe_send(port, "GET / HTTP/1.1\r\nHost: shapoclyack.invalid\r\nAuthorization: NTLM " + type1 + "\r\nConnection: close\r\n\r\n", 1500);
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
    if code == "200" || code == "403" { return; }
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
    let challenge = "";
    for line in header_block.split("\n") {
        let l = line;
        l.trim();
        let lower = l.to_lower();
        if lower.starts_with("www-authenticate:") {
            let raw = l.sub_string(17);
            raw.trim();
            let scheme = raw.to_lower();
            if scheme.starts_with("ntlm ") {
                challenge = raw.sub_string(5);
                challenge.trim();
            } else if raw == "ntlm" {
                challenge = "";
            }
        }
    }
    if challenge.len() == 0 { return; }
    if challenge.len() < 16 || challenge.len() % 4 != 0 || !is_base64(challenge) {
        throw "NTLM challenge is not a valid base64 string";
    }
    if !challenge.starts_with("TlRMTVNTUAAC") {
        return;
    }
    return #{
        title: "HTTP NTLM Type2 challenge observed",
        severity: "LOW",
        summary: "The server replied to an unauthenticated NTLM Type1 with a Type2 challenge over plain HTTP. Host and domain names from the challenge are not copied; no Type3 or credentials were sent.",
        evidence: "WWW-Authenticate header returned a well-formed NTLM Type2 challenge."
    };
}
