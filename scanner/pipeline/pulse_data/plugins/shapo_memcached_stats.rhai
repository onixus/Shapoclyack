// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// A bounded read-only ASCII stats request; no item reads or modifications.
fn name() { "shapo_memcached_stats" }
fn description() { "Detect unauthenticated Memcached statistics disclosure." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "memcached" || service == "memcache" || (unnamed && port == 11211)) { return; }
    let reply = probe_send(port, "stats\r\nquit\r\n", 1500);
    if !reply.starts_with("STAT ") || !reply.ends_with("END\r\n") { throw "incomplete or unexpected Memcached stats response"; }
    if !(reply.contains("\nSTAT version ") || reply.starts_with("STAT version ") || reply.contains("\nSTAT pid ") || reply.starts_with("STAT pid ")) {
        throw "Memcached stats response lacks identifying fields";
    }
    return #{title: "Memcached statistics available without authentication", severity: "LOW",
        summary: "The service returned statistics without credentials. This does not establish item access, write access, or UDP exposure.",
        evidence: "Unauthenticated stats command returned a complete Memcached response."};
}
