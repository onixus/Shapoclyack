// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One DRDA EXCSAT command; an EXCSATRD reply means the server answered.
// No SQL, security or database access is attempted.
fn name() { "shapo_drda_exchange" }
fn description() { "Detect a DRDA server answering an Exchange Server Attributes command." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated hex data"; }
    let digits = "0123456789abcdef";
    let a = digits.index_of(data.sub_string(pos * 2, 1));
    let b = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if a < 0 || b < 0 { throw "invalid hex data"; }
    return a * 16 + b;
}
fn be16(data, pos) {
    return octet(data, pos) * 256 + octet(data, pos + 1);
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "drda" || (unnamed && port == 50000)) { return; }
    let reply = probe_send_hex(port, "0021d001000110411404001014030003147c000714400001115e0009736861706f", 1500).to_lower();
    if reply.len() == 0 { throw "empty DRDA reply"; }
    if reply.len() < 16 { throw "truncated DRDA reply"; }
    let length = be16(reply, 0);
    if length < 6 || length * 2 != reply.len() { throw "DRDA DDM length mismatch"; }
    if octet(reply, 2) != 0xd0 { throw "DRDA DDM magic mismatch"; }
    if be16(reply, 6) == 0x1440 {
        return #{
            title: "DRDA EXCSAT answered",
            severity: "LOW",
            summary: "The DRDA server returned an Exchange Server Attributes Reply (EXCSATRD) without authentication. SQL, security and database access were not attempted.",
            evidence: "DRDA EXCSATRD received in response to EXCSAT."
        };
    }
    return;
}
