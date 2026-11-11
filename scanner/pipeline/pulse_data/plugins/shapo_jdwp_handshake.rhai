// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One JDWP handshake; a echoed handshake means the debug port is open.
// No JDWP commands are sent.
fn name() { "shapo_jdwp_handshake" }
fn description() { "Detect an open Java Debug Wire Protocol handshake port." }
fn ports() { [] }
fn run() {
    if service == "jdwp" {
        let reply = probe_send(port, "JDWP-Handshake", 1500);
        if reply.len() == 0 { throw "empty JDWP handshake reply"; }
        if reply == "JDWP-Handshake" {
            return #{
                title: "JDWP handshake accepted",
                severity: "LOW",
                summary: "The server echoed the JDWP handshake, indicating an open Java debug port. No JDWP commands were sent.",
                evidence: "JDWP-Handshake was echoed by the server."
            };
        }
        throw "unexpected JDWP handshake reply";
    } else {
        return;
    }
}
