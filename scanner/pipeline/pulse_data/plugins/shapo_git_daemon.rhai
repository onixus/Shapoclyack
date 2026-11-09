// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One pkt-line upload-pack request for a single fixed inert path; ref names
// and objects are never read. A parsed advertisement up to the flush packet is
// finding, an ERR line is a refusal, and a stream that ends without either is
// truncated. No path guessing.
fn name() { "shapo_git_daemon" }
fn description() { "Detect git-daemon repositories exposing a ref advertisement without authentication." }
fn ports() { [] }
fn nib(data, pos) {
    if pos < 0 || pos + 1 > data.len() { throw "truncated git daemon hex"; }
    let digits = "0123456789abcdef";
    let v = digits.index_of(data.sub_string(pos, 1));
    if v < 0 { throw "invalid hex in git daemon reply"; }
    return v;
}
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated git daemon hex field"; }
    let digits = "0123456789abcdef";
    let hi = digits.index_of(data.sub_string(pos * 2, 1));
    let lo = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if hi < 0 || lo < 0 { throw "invalid hex in git daemon reply"; }
    return hi * 16 + lo;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "git" || (unnamed && port == 9418)) { return; }
    let reply = probe_send_hex(port, "303034326769742d75706c6f61642d7061636b202f736861706f636c7961636b2e696e76616c696400686f73743d736861706f636c7961636b2e696e76616c696400", 1500).to_lower();
    if reply.len() == 0 || reply.len() % 2 != 0 || reply.len() > 32768 { throw "invalid git daemon reply size"; }
    let blen = reply.len() / 2;
    let bpos = 0;
    let saw_ref = false;
    while bpos < blen {
        if bpos + 4 > blen { throw "git daemon stream cut inside a pkt-line length"; }
        let hp = bpos * 2;
        let n = nib(reply, hp) * 4096 + nib(reply, hp + 1) * 256 + nib(reply, hp + 2) * 16 + nib(reply, hp + 3);
        if n == 0 {
            if !saw_ref { throw "git daemon flush arrived before any ref line"; }
            return #{title: "Git daemon exposes ref advertisement without authentication", severity: "LOW",
                summary: "The daemon answered one upload-pack request for a fixed inert path with a ref advertisement terminated by a flush packet. Ref names were not recorded, objects were not requested, and receive-pack was not attempted.",
                evidence: "A git-upload-pack request for the fixed path returned a parsed advertisement ending in a flush packet."};
        }
        if n < 4 || bpos + n > blen { throw "git daemon pkt-line length mismatch"; }
        if n >= 8 && reply.sub_string((bpos + 4) * 2, 8) == "45525220" { return; }
        if n == 4 || octet(reply, bpos + n - 1) != 10 { throw "malformed git daemon ref line"; }
        saw_ref = true;
        bpos += n;
    }
    throw "git daemon stream ended before a flush packet";
}
