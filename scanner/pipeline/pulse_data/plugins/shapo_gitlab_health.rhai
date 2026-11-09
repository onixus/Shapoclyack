// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One plain-HTTP GET of the built-in health endpoint. Not requested:
// readiness, the database check text and the REST API. The body is one fixed
// health phrase plus at most one trailing LF or CRLF. A 401/403 or a redirect
// is clean.
fn name() { "shapo_gitlab_health" }
fn description() { "Detect a GitLab health endpoint answering without authentication." }
fn ports() { [] }
fn run() {
    if !(service == "gitlab") { return; }
    let reply = probe_send(port, "GET /-/health HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    let parts = http_read(reply);
    let code = parts[0];
    let body = parts[2];
    if code == 401 || code == 403 { return; }
    if code == 301 || code == 302 || code == 303 || code == 307 || code == 308 { return; }
    if code != 200 { throw "unexpected HTTP status " + code + " from the health endpoint"; }
    if body != "GitLab OK" && body != "GitLab OK\n" && body != "GitLab OK\r\n" { throw "unexpected health reply body"; }
    return #{
        title: "GitLab health endpoint answered without authentication",
        severity: "LOW",
        summary: "The health endpoint returned its fixed body without credentials. Readiness, the database check text and the REST API were not requested.",
        evidence: "Unauthenticated GET of the health endpoint returned HTTP 200 with the complete fixed health body."
    };
}

// --- HTTP helpers (one reply, read to EOF) ---------------------------------

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

// [status_code, headers_block, body]. Raises when the reply is not one
// complete HTTP reply: a bad status line, headers cut off, truncated chunk
// framing, or a Content-Length that disagrees with the body read to EOF.
// One chunked body is decoded. When both encodings are present, chunked wins.
fn http_read(reply) {
    if reply.len() < 8 || !reply.starts_with("HTTP/") {
        throw "reply is not HTTP";
    }
    let nl = reply.index_of("\n");
    if nl < 0 {
        throw "HTTP reply is cut off inside the status line";
    }
    let line = reply.sub_string(0, nl);
    line.trim();
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
        body = decode_chunked(body);
    } else {
        let wanted = -1;
        for hline in head.split("\n") {
            let t = hline;
            t.trim();
            t = t.to_lower();
            if t.starts_with("content-length:") {
                let v = t.sub_string(15, t.len() - 15);
                v.trim();
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
    }
    [code, head, body]
}
