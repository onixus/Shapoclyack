// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One NBD new-style handshake; a returned INIT_PASSWD means the server spoke.
// No export name is requested.
fn name() { "shapo_nbd_hello" }
fn description() { "Detect a Network Block Device server answering the new-style handshake." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "nbd" || (unnamed && port == 10809)) { return; }
    let reply = probe_send_hex(port, "4e42444d4147494349484156454f505400000001", 1500).to_lower();
    if reply.len() == 0 { throw "empty NBD handshake reply"; }
    if reply.len() < 16 { throw "truncated NBD handshake reply"; }
    if reply.sub_string(0, 16) == "4e42444d41474943" {
        return #{
            title: "NBD handshake answered",
            severity: "LOW",
            summary: "The server returned the NBD INIT_PASSWD magic after the new-style client handshake. No export name or data operation was sent.",
            evidence: "NBD INIT_PASSWD magic was returned."
        };
    }
    throw "unexpected NBD handshake reply";
}
