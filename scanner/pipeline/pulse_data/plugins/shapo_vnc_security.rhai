// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// Security advertisement only: no selection, ClientInit or desktop data.
fn name() { "shapo_vnc_security" }
fn description() { "Observe RFB/VNC security types without starting a desktop session." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "vnc" || banner.to_lower().starts_with("rfb ") || (unnamed && port == 5900) || (unnamed && port == 5901) || (unnamed && port == 5902) || (unnamed && port == 5903) || (unnamed && port == 5904) || (unnamed && port == 5905) || (unnamed && port == 5906) || (unnamed && port == 5907) || (unnamed && port == 5908) || (unnamed && port == 5909)) { return; }
    let result = probe_vnc_security(port, 1500);
    if result.contains("error") { throw "VNC security assessment inconclusive: " + result.error; }
    if result.none_advertised {
        return #{title: "VNC advertises security type None", severity: "MEDIUM", requires_confirmation: true, confidence: 82, summary: "The RFB security advertisement includes type1 (None). No security type was selected and no desktop session was opened, so completed unauthenticated access was not tested.", evidence: "RFB=" + result.version + "; security_types=" + result.security_types};
    }
    return #{title: "VNC security type inventory observed", severity: "INFO", summary: "The listed security types are the peer's negotiation advertisement; authentication completion and desktop access were not tested.", evidence: "RFB=" + result.version + "; security_types=" + result.security_types};
}
