// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One legacy OP_QUERY carrying an isMaster command on admin.$cmd; no
// listDatabases, no find, no credentials. The reply must be a single BSON
// document whose declared lengths close exactly.
fn name() { "shapo_mongodb_hello" }
fn description() { "Detect a MongoDB hello (isMaster) reply served without authentication." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated hex data"; }
    let digits = "0123456789abcdef";
    let a = digits.index_of(data.sub_string(pos * 2, 1));
    let b = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if a < 0 || b < 0 { throw "invalid hex data"; }
    return a * 16 + b;
}
fn le32(data, pos) {
    return octet(data, pos) + octet(data, pos + 1) * 256 + octet(data, pos + 2) * 65536 + octet(data, pos + 3) * 16777216;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "mongodb" || (unnamed && port == 27017) || (unnamed && port == 27018) || (unnamed && port == 27019)) { return; }
    // OP_QUERY on admin.$cmd, request id sent as the raw bytes "SHAP",
    // query document {isMaster: 1} assembled from the wire specification.
    let reply = probe_send_hex(port, "3a0000005348415000000000d40700000000000061646d696e2e24636d64000000000001000000130000001069734d6173746572000100000000", 1500).to_lower();
    if reply.len() < 82 || reply.len() % 2 != 0 { throw "truncated MongoDB wire reply"; }
    let size = le32(reply, 0);
    if size < 41 || size * 2 != reply.len() { throw "MongoDB message length mismatch"; }
    if le32(reply, 12) != 1 { throw "unexpected MongoDB reply opcode"; }
    if le32(reply, 8) != 0x50414853 { throw "MongoDB reply is not correlated with the request"; }
    if le32(reply, 32) != 1 { throw "unexpected MongoDB reply document count"; }
    let doc_len = le32(reply, 36);
    let doc_end = 36 + doc_len;
    if doc_len < 5 || doc_end != size { throw "MongoDB document length mismatch"; }
    // Walk the top-level elements of the single reply document. Fixed-width
    // BSON types are skipped by width; a regex is two C strings. Unknown types
    // are an error.
    let name_ismaster = "69736d6173746572";
    let name_maxbson = "6d617842736f6e4f626a65637453697a65";
    let name_errmsg = "6572726d7367";
    let name_ok = "6f6b";
    let pos = 40;
    let saw_marker = false;
    let saw_error = false;
    while pos < doc_end - 1 {
        let t = octet(reply, pos);
        pos += 1;
        let name_start = pos;
        while octet(reply, pos) != 0 { pos += 1; }
        let name = reply.sub_string(name_start * 2, (pos - name_start) * 2);
        pos += 1;
        let skip = 0;
        if t == 1 { skip = 8; }
        else if t == 2 || t == 13 || t == 14 {
            let n = le32(reply, pos);
            if n < 1 { throw "invalid BSON string length"; }
            skip = 4 + n;
        } else if t == 3 || t == 4 {
            let n = le32(reply, pos);
            if n < 5 { throw "invalid embedded BSON document length"; }
            skip = n;
        } else if t == 5 {
            let n = le32(reply, pos);
            skip = 5 + n;
        } else if t == 6 || t == 10 || t == 127 || t == 255 { skip = 0; }
        else if t == 7 { skip = 12; }
        else if t == 8 { skip = 1; }
        else if t == 9 || t == 17 || t == 18 { skip = 8; }
        else if t == 11 {
            let cpos = pos;
            let strings = 0;
            while strings < 2 {
                if cpos >= doc_end - 1 { throw "BSON regex overruns the document"; }
                if octet(reply, cpos) == 0 { strings += 1; }
                cpos += 1;
            }
            skip = cpos - pos;
        } else if t == 12 {
            let n = le32(reply, pos);
            skip = 16 + n;
        } else if t == 15 {
            let n = le32(reply, pos);
            if n < 5 { throw "invalid BSON code_w_s length"; }
            skip = n;
        } else if t == 16 { skip = 4; }
        else { throw "unsupported BSON element type in hello reply"; }
        if pos + skip > doc_end - 1 { throw "BSON element overruns the document"; }
        if name == name_errmsg { saw_error = true; }
        if name == name_ismaster || name == name_maxbson { saw_marker = true; }
        if t == 1 && name == name_ok {
            let zero = true;
            for k in 0..8 { if octet(reply, pos + k) != 0 { zero = false; } }
            if zero { saw_error = true; }
        }
        if t == 16 && name == name_ok && le32(reply, pos) == 0 { saw_error = true; }
        pos += skip;
    }
    if pos != doc_end - 1 { throw "BSON element walk mismatch"; }
    if octet(reply, doc_end - 1) != 0 { throw "unterminated BSON document"; }
    if saw_marker && !saw_error {
        return #{
            title: "MongoDB hello answered without authentication",
            severity: "LOW",
            summary: "An isMaster command on admin.$cmd returned a complete reply document without credentials. Databases, collections and documents were not listed or read.",
            evidence: "Unauthenticated isMaster on admin.$cmd returned a complete BSON reply document."
        };
    }
    if saw_error && !saw_marker { return; }
    throw "unrecognized MongoDB hello reply document";
}
