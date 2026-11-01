// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Check only unauthenticated INFO SERVER; do not read or change keys.
fn name() { "shapo_redis_info" }
fn description() { "Detect Redis server information accessible without authentication." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "redis" || (unnamed && port == 6379)) { return; }
    let reply = probe_send(port, "*2\r\n$4\r\nINFO\r\n$6\r\nSERVER\r\n", 1500);
    if (reply.starts_with("-NOAUTH ") || reply.starts_with("-NOPERM ")) && reply.ends_with("\r\n") { return; }
    if !reply.starts_with("$") { throw "unexpected Redis INFO response"; }
    let split = reply.index_of("\r\n");
    if split < 2 { throw "incomplete Redis bulk response header"; }
    let length = parse_int(reply.sub_string(1, split - 1));
    if length < 1 || length > 15000 { throw "invalid Redis INFO length"; }
    let body = reply.sub_string(split + 2);
    if body.len() != length + 2 || !body.ends_with("\r\n") { throw "incomplete Redis INFO response"; }
    if !(body.contains("\nredis_version:") || body.contains("\nkeydb_version:") || body.contains("\ndragonfly_version:")) {
        throw "Redis INFO response lacks a supported server version";
    }
    return #{title: "Redis server information available without authentication", severity: "LOW",
        summary: "INFO SERVER returned server information without credentials. This does not prove access to keys or write commands.",
        evidence: "Unauthenticated INFO SERVER returned a complete Redis-compatible server response."};
}
