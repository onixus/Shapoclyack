// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// No authentication; only a verified curve25519/Ed25519 key exchange.
fn name() { "shapo_ssh_hostkey" }
fn description() { "Observe a signature-verified SSH Ed25519 host-key fingerprint." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "ssh" || (unnamed && port == 22)) { return; }
    if protocol != "tcp" { return; }
    let evidence = probe_ssh_hostkey(port, 1500);
    if evidence.starts_with("pulse-error:") { throw evidence; }
    if !evidence.starts_with("ssh-ed25519 SHA256:") { throw "unexpected SSH host-key observation"; }
    return #{title: "SSH host key observed", severity: "INFO", summary: "Ed25519 host-key fingerprint from a signature-verified curve25519 key exchange. This proves key possession on this connection, not known-host trust, host identity or absence of weak algorithms.", evidence: evidence};
}
