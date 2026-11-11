// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One JRMP handshake; a protocol-ok byte means a Java RMI registry answered.
// No remote object listing is requested.
fn name() { "shapo_rmi_registry" }
fn description() { "Detect a Java RMI registry responding to the JRMP handshake." }
fn ports() { [] }
fn run() {
    if service != "rmi" { return; }
    let reply = probe_send_hex(port, "4a524d490002", 1500).to_lower();
    if reply.len() == 0 { throw "empty RMI handshake reply"; }
    if reply.len() < 2 { throw "truncated RMI handshake reply"; }
    let first = reply.sub_string(0, 2);
    if first == "4e" {
        return;
    }
    if first == "4f" {
        return #{
            title: "Java RMI registry answered",
            severity: "LOW",
            summary: "The server accepted the JRMP protocol handshake, indicating a reachable Java RMI registry. Remote object names were not listed.",
            evidence: "JRMP handshake returned the protocol-ok marker."
        };
    }
    throw "unexpected RMI handshake reply";
}
