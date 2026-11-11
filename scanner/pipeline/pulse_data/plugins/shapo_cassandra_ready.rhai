// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One CQL STARTUP without credentials; READY means an anonymous session.
// No queries or writes are sent.
fn name() { "shapo_cassandra_ready" }
fn description() { "Detect a Cassandra CQL STARTUP answered with READY without credentials." }
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
    if !(service == "cassandra" || (unnamed && port == 9042)) { return; }
    // Protocol v3 header is 9 bytes: version, flags, 2-byte stream, opcode, length.
    let reply = probe_send_hex(port, "0300000001000000160001000b43514c5f56455253494f4e0005332e302e30", 1500).to_lower();
    if reply.len() == 0 { throw "empty Cassandra CQL reply"; }
    if reply.len() < 18 { throw "truncated Cassandra CQL reply"; }
    if octet(reply, 0) != 0x83 { throw "Cassandra CQL response version mismatch"; }
    let opcode = octet(reply, 4);
    let size = be32(reply, 5);
    if size * 2 != reply.len() - 18 { throw "Cassandra CQL body length mismatch"; }
    if opcode == 0x03 { return; }
    if opcode == 0x02 {
        return #{
            title: "Cassandra CQL READY answered without authentication",
            severity: "LOW",
            summary: "A CQL STARTUP request without credentials was accepted and the server returned READY. Queries, keyspaces and writes were not attempted.",
            evidence: "CQL STARTUP returned READY without authentication."
        };
    }
    throw "unexpected Cassandra CQL response opcode";
}
