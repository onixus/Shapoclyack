// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// Observe an NTLM type2 challenge; no type3, credentials or desktop session.
fn name() { "shapo_rdp_ntlm_info" }
fn description() { "Observe RDP CredSSP NTLM host/domain/build information." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "rdp" || service == "ms-wbt-server" || (unnamed && port == 3389)) { return; }
    let result = probe_rdp_ntlm(port, 5000);
    if result.contains("error") { throw "RDP NTLM assessment inconclusive: " + result.error; }
    return #{title: "RDP NTLM host information observed", severity: "INFO", confidence: 70, requires_confirmation: true, summary: "The peer disclosed host/domain/build fields in an NTLM type2 challenge after X.224 and TLS negotiation. This is unauthenticated inventory; no credentials, NTLM type3 or desktop-session messages were sent.", evidence: "CredSSP NTLM type2=" + result};
}
