// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Reimplementation of nuclei-templates v9.9.4 exposed-zookeeper (MIT).
// The result concerns the envi diagnostic only, not znode access.
fn name() { "shapo_zookeeper_envi" }
fn description() { "Detect ZooKeeper environment diagnostics available without credentials." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "zookeeper" || (unnamed && port == 2181)) { return; }
    let reply = probe_send(port, "envi", 1500);
    if !reply.starts_with("Environment:\n") || !reply.contains("\nzookeeper.version=") || !reply.ends_with("\n") {
        throw "incomplete, disabled, or unexpected ZooKeeper envi response";
    }
    return #{title: "ZooKeeper environment diagnostics available without authentication", severity: "LOW",
        summary: "The envi diagnostic returned environment information without credentials. This does not establish znode read or write access.",
        evidence: "An unauthenticated ZooKeeper envi response contained its version field."};
}
