// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One Bolt version-offer: the magic preamble, then offers 5.4, 5.0, 4.4 and
// 4.0 in one frame. Any non-zero answer means the server picked a version;
// an all-zero four-byte answer is a refusal. HELLO, LOGON, RUN and PULL are
// never sent, so there is no login and no graph request.
fn name() { "shapo_neo4j_discovery" }
fn description() { "Detect Neo4j Bolt servers that answer the version handshake without authentication." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "neo4j" || (unnamed && port == 7687)) { return; }
    let reply = probe_send_hex(port, "6060b01700000405000000050000040400000004", 1500).to_lower();
    if reply.len() == 0 { throw "empty Bolt handshake reply"; }
    if reply.len() % 2 != 0 || reply.len() > 32768 { throw "malformed Bolt handshake reply"; }
    if reply.len() < 8 { throw "truncated Bolt version reply"; }
    if reply == "00000000" { return; }
    if reply.sub_string(0, 8) == "00000000" { throw "unverified Bolt reply with a zero version prefix"; }
    return #{
        title: "Neo4j Bolt server answered the version handshake without authentication",
        severity: "LOW",
        summary: "The server picked a Bolt version from the 5.4/5.0/4.4/4.0 offers. Login was not attempted and no graph request was sent.",
        evidence: "The server selected a Bolt protocol version after the version negotiation preamble."
    };
}
