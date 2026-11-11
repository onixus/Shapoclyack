// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One EPMD names request; a node list reply means the port mapper answered.
// No node connection is attempted.
fn name() { "shapo_epmd_names" }
fn description() { "Detect an Erlang Port Mapper Daemon names reply." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "epmd" || (unnamed && port == 4369)) { return; }
    // EPMD reads a 2-byte length before the names tag.
    let reply = probe_send_hex(port, "00016e", 1500).to_lower();
    if reply.len() == 0 { throw "empty EPMD names reply"; }
    if reply.len() < 8 { throw "truncated EPMD names reply"; }
    // NAMES_RESP starts with a 4-byte port. No node line after it is an empty list.
    if reply.len() == 8 { return; }
    let names = reply.sub_string(8);
    if !names.contains("0a") { throw "truncated EPMD names reply"; }
    return #{
        title: "EPMD names listing answered",
        severity: "LOW",
        summary: "The Erlang Port Mapper Daemon returned a node list in response to the names command. Node names were not copied.",
        evidence: "EPMD names reply contained a node entry."
    };
}
