// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One CONNECT with no user, pass or token, plus one PING. The finding is a
// PONG line in the reply; a broker that rejects the anonymous CONNECT says so
// with -ERR 'Authorization Violation'. The INFO line is never parsed and its
// JSON is never copied: it names the server and client addresses. SUB and PUB
// are never sent.
fn name() { "shapo_nats_info" }
fn description() { "Detect NATS brokers that answer an anonymous CONNECT and PING." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "nats" || (unnamed && port == 4222)) { return; }
    let reply = probe_send(port, "CONNECT {\"verbose\":false,\"pedantic\":false,\"lang\":\"shapo\",\"version\":\"1\",\"protocol\":1}\r\nPING\r\n", 1500);
    if reply.len() == 0 { throw "empty NATS broker reply"; }
    let saw_pong = false;
    let auth_refusal = false;
    let other_err = false;
    for raw in reply.split("\n") {
        let line = raw;
        line.trim();
        if line == "" { continue; }
        if line == "PONG" { saw_pong = true; }
        if line.starts_with("-ERR") {
            if line.contains("Authorization") || line.contains("Authentication") {
                auth_refusal = true;
            } else {
                other_err = true;
            }
        }
    }
    if other_err || (saw_pong && auth_refusal) { throw "contradictory NATS broker reply"; }
    if saw_pong {
        return #{
            title: "NATS broker answered CONNECT and PING without credentials",
            severity: "LOW",
            summary: "The broker replied PONG to a CONNECT carrying no user, pass or token, followed by one PING. Login, subscriptions and publications were not attempted.",
            evidence: "The broker answered an anonymous CONNECT+PING with a PONG line."
        };
    }
    if auth_refusal && !other_err { return; }
    throw "NATS broker reply has no PONG and no authentication refusal";
}
