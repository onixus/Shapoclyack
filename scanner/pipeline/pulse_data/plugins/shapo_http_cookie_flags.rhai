// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One HEAD request; report any Set-Cookie header that lacks the HttpOnly flag.
// Secure on plain HTTP is not treated as a defect because the connection is not TLS.
fn name() { "shapo_http_cookie_flags" }
fn description() { "Detect Set-Cookie headers missing the HttpOnly flag on plain HTTP." }
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
    let greeting = banner.to_lower();
    if !(service == "http" || greeting.starts_with("http/")) { return; }
    let reply = probe_send(port, "HEAD / HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
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
    let cookies = [];
    for line in header_block.split("\n") {
        let l = line;
        l.trim();
        let lower = l.to_lower();
        if lower.starts_with("set-cookie:") {
            cookies.push(l);
        }
    }
    if cookies.len() == 0 { return; }
    let missing = "";
    for c in cookies {
        let value = c.sub_string(11);
        value.trim();
        let has_httponly = false;
        for token in value.split(";") {
            let t = token;
            t.trim();
            if t.to_lower() == "httponly" { has_httponly = true; }
        }
        if !has_httponly {
            missing = c;
            break;
        }
    }
    if missing.len() == 0 { return; }
    return #{
        title: "HTTP Set-Cookie missing HttpOnly flag",
        severity: "LOW",
        summary: "A Set-Cookie header was returned without the HttpOnly attribute on plain HTTP. The cookie value and any associated client-side attack surface were not verified; Secure is not assessed because the request is not TLS.",
        evidence: "Set-Cookie header lacks HttpOnly: " + head(missing, 80)
    };
}
