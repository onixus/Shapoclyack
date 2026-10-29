// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Reimplementation of the rsync-list-modules check in nuclei-templates
// v9.9.4 (MIT): request only the list, never open a module or read a file.
fn name() { "shapo_rsync_modules" }
fn description() { "Detect listable rsync daemon modules without credentials." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "rsync" || (unnamed && port == 873)) { return; }
    let reply = probe_send(port, "@RSYNCD: 29.0\n#list\n", 1500);
    if !reply.starts_with("@RSYNCD: ") || !reply.ends_with("@RSYNCD: EXIT\n") {
        throw "incomplete or unexpected rsync module listing";
    }
    let lines = reply.split("\n");
    let count = 0;
    for i in 1..(lines.len() - 2) {
        let line = lines[i];
        line.trim();
        if line.starts_with("@") { throw "unexpected rsync control message"; }
        if line != "" { count += 1; }
    }
    if count > 0 {
        return #{title: "Rsync modules listed without authentication", severity: "LOW",
            summary: "The daemon listed one or more modules without credentials. This does not establish file read or write access.",
            evidence: "An unauthenticated rsync module listing completed and was non-empty."};
    }
}
