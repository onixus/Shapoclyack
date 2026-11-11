// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Confirms: the server selects the no-authentication method (0x00) in answer
// to a SOCKS5 greeting that offers exactly that one method. Not checked:
// CONNECT, BIND or UDP ASSOCIATE - no tunnel request is ever sent, so no
// destination address exists. A 05 ff reply or any other method byte is a
// refusal and is not a finding.
fn name() { "shapo_socks_noauth" }
fn description() { "Detect a SOCKS5 proxy that offers the no-authentication method." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "socks" || (unnamed && port == 1080)) { return; }
    let reply = probe_send_hex(port, "050100", 1500).to_lower();
    if reply.len() == 0 { throw "empty SOCKS5 method-selection reply"; }
    if reply.len() != 4 { throw "SOCKS5 method-selection reply is not exactly two bytes"; }
    if reply.sub_string(0, 2) != "05" { throw "SOCKS5 reply has a version other than 5"; }
    if reply == "0500" {
        return #{
            title: "SOCKS5 proxy accepts connections without authentication",
            severity: "LOW",
            summary: "The server answered a SOCKS5 greeting (version 5, one method: no authentication) with 05 00, selecting the no-authentication method. No CONNECT, BIND or UDP ASSOCIATE request was sent, so no tunnel was opened.",
            evidence: "The server selected the SOCKS5 no-authentication method in reply to a greeting that offered method 0 only. No destination address exists because no tunnel request was sent."
        };
    }
}
