// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// X.224 negotiation only. No authentication, desktop session or NTLM exchange.
fn name() { "shapo_rdp_negotiation" }
fn description() { "Test whether standard RDP security is accepted without NLA." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "rdp" || service == "ms-wbt-server" || (unnamed && port == 3389)) { return; }
    let reply = probe_send_hex(port, "030000130ee000000000000100080000000000", 1500).to_lower();
    if reply.len() != 38 || !reply.starts_with("030000130ed0") || reply.sub_string(20, 2) != "00" || reply.sub_string(26, 4) != "0800" { throw "invalid or truncated RDP negotiation response"; }
    let kind = reply.sub_string(22, 2);
    let value = reply.sub_string(30, 8);
    if kind == "03" {
        // SSL_REQUIRED_BY_SERVER and HYBRID_REQUIRED_BY_SERVER are explicit refusals.
        if value == "01000000" || value == "05000000" || value == "06000000" { return; }
        throw "RDP negotiation failed without an authentication-policy conclusion";
    }
    if kind != "02" || value != "00000000" { throw "RDP selected a protocol not offered by this probe"; }
    return #{ title: "RDP accepts standard security without NLA", severity: "MEDIUM", summary: "The X.224 connection confirm accepts standard RDP security when no enhanced-security protocol was offered. NLA is therefore not mandatory for negotiation. Login, encryption strength and password policy were not tested.", evidence: "RDP_NEG_RSP selectedProtocol=0 (PROTOCOL_RDP)" };
}
