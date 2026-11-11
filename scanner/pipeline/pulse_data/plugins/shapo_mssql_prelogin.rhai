// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One TDS PRELOGIN packet; a parsed response means the engine answered.
// No login, query or command is sent.
fn name() { "shapo_mssql_prelogin" }
fn description() { "Detect a Microsoft SQL Server answering a TDS PRELOGIN request." }
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
fn be32(data, pos) {
    return octet(data, pos) * 16777216 + octet(data, pos + 1) * 65536 + octet(data, pos + 2) * 256 + octet(data, pos + 3);
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "mssql" || (unnamed && port == 1433)) { return; }
    let reply = probe_send_hex(port, "1201002f00000100000000000601000600010200070001030008000404000c0001ff00000000000000000000000000", 1500).to_lower();
    if reply.len() == 0 { throw "empty TDS PRELOGIN reply"; }
    if reply.len() < 16 { throw "truncated TDS PRELOGIN reply"; }
    if octet(reply, 0) != 0x04 { throw "TDS PRELOGIN reply type mismatch"; }
    let length = be16(reply, 2);
    if length < 8 || length * 2 != reply.len() { throw "TDS PRELOGIN length mismatch"; }
    return #{
        title: "Microsoft SQL Server PRELOGIN answered",
        severity: "LOW",
        summary: "The SQL Server engine returned a complete TDS PRELOGIN response, disclosing version and encryption negotiation. No login, query or TDS command was sent.",
        evidence: "TDS PRELOGIN returned a complete response."
    };
}
