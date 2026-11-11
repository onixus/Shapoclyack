// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One GIOP LocateRequest; a LocateReply means an ORB answered.
// No object invocation is performed.
fn name() { "shapo_giop_locate" }
fn description() { "Detect a CORBA GIOP/IIOP endpoint answering a LocateRequest." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated hex data"; }
    let digits = "0123456789abcdef";
    let a = digits.index_of(data.sub_string(pos * 2, 1));
    let b = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if a < 0 || b < 0 { throw "invalid hex data"; }
    return a * 16 + b;
}
fn be32(data, pos) {
    return octet(data, pos) * 16777216 + octet(data, pos + 1) * 65536 + octet(data, pos + 2) * 256 + octet(data, pos + 3);
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "giop" || (unnamed && port == 2809)) { return; }
    let reply = probe_send_hex(port, "47494f50010000030000000400000001", 1500).to_lower();
    if reply.len() == 0 { throw "empty GIOP locate reply"; }
    if reply.len() < 24 { throw "truncated GIOP locate reply"; }
    if reply.sub_string(0, 8) != "47494f50" { throw "GIOP magic mismatch"; }
    if octet(reply, 7) != 4 { throw "GIOP reply is not LocateReply"; }
    let size = be32(reply, 8);
    if size < 4 || 12 + size > reply.len() / 2 { throw "GIOP LocateReply size mismatch"; }
    return #{
        title: "GIOP LocateRequest answered",
        severity: "LOW",
        summary: "The server returned a GIOP LocateReply, indicating a reachable CORBA IIOP endpoint. No object method was invoked.",
        evidence: "GIOP LocateReply received."
    };
}
