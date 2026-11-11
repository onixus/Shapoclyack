// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One iSCSI Login request without authentication; a Login Response means the target answered.
// No session, digest negotiation or LUN access is attempted.
fn name() { "shapo_iscsi_text" }
fn description() { "Detect an iSCSI target answering a login request without credentials." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated hex data"; }
    let digits = "0123456789abcdef";
    let a = digits.index_of(data.sub_string(pos * 2, 1));
    let b = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if a < 0 || b < 0 { throw "invalid hex data"; }
    return a * 16 + b;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "iscsi" || (unnamed && port == 3260)) { return; }
    let reply = probe_send_hex(port, "430000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000", 1500).to_lower();
    if reply.len() == 0 { throw "empty iSCSI reply"; }
    if reply.len() < 96 { throw "truncated iSCSI reply"; }
    let opcode = octet(reply, 0) & 0x7f;
    if opcode == 0x3f { return; }
    if opcode != 0x23 { throw "unexpected iSCSI response opcode"; }
    if octet(reply, 36) != 0 { return; }
    return #{
        title: "iSCSI login answered without credentials",
        severity: "LOW",
        summary: "An iSCSI Login request without AuthMethod or CHAP was answered with a successful Login Response. No session, digest negotiation or LUN access was attempted.",
        evidence: "iSCSI Login Response received with status class zero."
    };
}
