// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Confirms: the tags endpoint of a local model server answers an anonymous
// request with its model catalog. Not checked: generation, pull and chat
// endpoints and any model content.
fn name() { "shapo_ollama_tags" }
fn description() { "Detect the Ollama API exposing its model list without authentication." }
fn ports() { [] }
fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "ollama" || (unnamed && port == 11434)) { return; }
    let reply = probe_send(port, "GET /api/tags HTTP/1.1\r\nHost: shapoclyack.invalid\r\nConnection: close\r\n\r\n", 1500);
    if reply.len() == 0 { throw "empty Ollama probe reply"; }
    let lines = reply.split("\n");
    let status = "";
    if lines.len() > 0 { status = lines[0].trim(); }
    if !status.starts_with("HTTP/") { throw "Ollama probe reply is not HTTP: " + head(reply, 60); }
    let parts = status.split(" ");
    if parts.len() < 2 || parts[1].len() != 3 { throw "unparseable HTTP status line: " + head(status, 60); }
    if parts[1] == "401" || parts[1] == "403" { return; }
    if parts[1] != "200" { throw "unexpected HTTP status from the Ollama tags endpoint"; }
    let sep4 = reply.index_of("\r\n\r\n");
    let sep2 = reply.index_of("\n\n");
    let at = -1;
    let body = reply;
    if sep4 >= 0 { at = sep4; body = reply.sub_string(sep4 + 4); }
    else if sep2 >= 0 { at = sep2; body = reply.sub_string(sep2 + 2); }
    if at < 0 { throw "no end of HTTP headers in the Ollama reply"; }
    let block = reply.sub_string(0, at).to_lower();
    let marker = "content-length:";
    let pos = block.index_of(marker);
    if pos >= 0 {
        let raw = block.sub_string(pos + marker.len());
        let end = raw.index_of("\n");
        if end >= 0 { raw = raw.sub_string(0, end); }
        raw = raw.trim();
        let want = parse_int(raw);
        if body.len() != want { throw "truncated Ollama reply body"; }
    }
    if !body.contains("\"models\"") { throw "Ollama tags reply has no models key"; }
    if !body.trim().ends_with("}") { throw "truncated JSON body in the Ollama reply"; }
    return #{
        title: "Ollama API exposes the model list without authentication",
        severity: "LOW",
        summary: "The tags endpoint returned the model catalog without credentials. Model names were not recorded; generation, pull and chat endpoints were not called.",
        evidence: "Anonymous GET /api/tags returned 200 with a JSON body containing the models key."
    };
}
