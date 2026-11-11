// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One TNS version request; an Accept with a version string means the listener answered.
// No CONNECT_DATA with a user or service is sent.
fn name() { "shapo_oracle_tns_version" }
fn description() { "Detect an Oracle TNS listener answering a VERSION request." }
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
    if !(service == "oracle" || (unnamed && port == 1521)) { return; }
    let reply = probe_send_hex(port, "002800000100000028434f4e4e4543545f444154413d28434f4d4d414e443d56455253494f4e2929", 1500).to_lower();
    if reply.len() == 0 { throw "empty Oracle TNS reply"; }
    if reply.len() < 16 { throw "truncated Oracle TNS reply"; }
    let length = be16(reply, 0);
    if length < 8 || length * 2 != reply.len() { throw "Oracle TNS length mismatch"; }
    if octet(reply, 4) != 0x02 { throw "Oracle TNS reply is not Accept"; }
    if reply.contains("56455253494f4e") {
        return #{
            title: "Oracle TNS listener answered VERSION",
            severity: "LOW",
            summary: "The Oracle TNS listener accepted a VERSION request and returned version information. No CONNECT_DATA with a user or service name was sent.",
            evidence: "TNS Accept response to a VERSION request was received."
        };
    }
    return;
}
