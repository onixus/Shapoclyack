// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One GET of the HTTP discovery document. Not requested: Bolt, Cypher or database lists.
fn name() { "shapo_neo4j_http" }
fn description() { "Detect a Neo4j HTTP discovery document answering without authentication." }
fn ports() { [] }
fn run() {
    if !(service == "neo4j") { return; }
    let reply = probe_send(port, "GET / HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    let parts = http_read(reply);
    let code = parts[0];
    let body = parts[2];
    if code == 401 || code == 403 || code == 301 || code == 302 || code == 303 || code == 307 || code == 308 { return; }
    if code != 200 { throw "unexpected HTTP status " + code + " from the discovery endpoint"; }
    if !json_object(body) { throw "discovery reply is not one complete JSON object"; }
    if !json_has_key(body, "neo4j_version") { throw "discovery JSON has no neo4j_version member"; }
    return #{
        title: "Neo4j HTTP discovery document readable without authentication",
        severity: "LOW",
        summary: "The HTTP discovery document was read without credentials. Bolt, Cypher and database lists were not requested.",
        evidence: "The HTTP discovery endpoint returned a complete document without authentication."
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

// The trimmed body is exactly one JSON object: it opens and closes with
// braces, so a reply cut mid-document does not slip through.
fn json_object(body) {
    let t = body;
    t.trim();
    t.len() >= 2 && t.starts_with("{") && t.ends_with("}")
}

// True when some "key" member is followed by optional whitespace, a colon,
// optional whitespace and the complete quoted word. A longer word such as
// "Welcomes" does not match, and spaces inside the value stay.
fn json_key_string(body, key, word) {
    let marker = "\"" + key + "\"";
    let want = "\"" + word + "\"";
    let rest = body;
    for guard in 0..64 {
        let i = rest.index_of(marker);
        if i < 0 { return false; }
        let tail = rest.sub_string(i + marker.len());
        let p = skip_ws(tail, 0);
        if p < tail.len() && tail.sub_string(p, 1) == ":" {
            p = skip_ws(tail, p + 1);
            if p + want.len() <= tail.len() && tail.sub_string(p, want.len()) == want { return true; }
        }
        rest = rest.sub_string(i + 1);
    }
    return false;
}

// True when some "key" member is followed by optional whitespace and a colon.
fn json_has_key(body, key) {
    let marker = "\"" + key + "\"";
    let rest = body;
    for guard in 0..64 {
        let i = rest.index_of(marker);
        if i < 0 { return false; }
        let tail = rest.sub_string(i + marker.len());
        let p = skip_ws(tail, 0);
        if p < tail.len() && tail.sub_string(p, 1) == ":" { return true; }
        rest = rest.sub_string(i + 1);
    }
    return false;
}

fn skip_ws(text, pos) {
    while pos < text.len() {
        let c = text.sub_string(pos, 1);
        if c != " " && c != "\t" && c != "\r" && c != "\n" { return pos; }
        pos += 1;
    }
    return pos;
}
