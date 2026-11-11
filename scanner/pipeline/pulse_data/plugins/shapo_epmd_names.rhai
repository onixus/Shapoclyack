// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One EPMD names request; a node list reply means the port mapper answered.
// No node connection is attempted.
fn name() { "shapo_epmd_names" }
fn description() { "Detect an Erlang Port Mapper Daemon names reply." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated hex data"; }
    let digits = "0123456789abcdef";
    let a = digits.index_of(data.sub_string(pos * 2, 1));
    let b = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if a < 0 || b < 0 { throw "invalid hex data"; }
    return a * 16 + b;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "epmd" || (unnamed && port == 4369)) { return; }
    let reply = probe_send_hex(port, "6e", 1500).to_lower();
    if reply.len() == 0 { throw "empty EPMD names reply"; }
    if reply.len() < 4 { throw "truncated EPMD names reply"; }
    let port = octet(reply, 0) * 256 + octet(reply, 1);
    if port < 1 || port > 65535 { throw "invalid EPMD port in names reply"; }
    if reply.contains("0a") {
        return #{
            title: "EPMD names listing answered",
            severity: "LOW",
            summary: "The Erlang Port Mapper Daemon returned a node list in response to the names command. Node names were not copied.",
            evidence: "EPMD names reply contained a node entry."
        };
    }
    throw "unexpected EPMD names reply";
}
