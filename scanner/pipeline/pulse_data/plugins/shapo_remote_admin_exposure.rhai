// SPDX-License-Identifier: MIT
// Copyright (c) onixus
//
// Derived from GenDec scripts/rdp_vnc_exposure_audit.rhai (GenDec v1.3.0, MIT;
// the Cargo.toml `license` field is the licence statement of that release).
// Changes for Shapoclyack: matches on the detected service as well as the
// port, so VNC on a display other than :0-:2 is found; VNC is confirmed from
// the "RFB" greeting instead of assumed from the port; HIGH lowered to LOW
// because the finding is reachability only; the summary says what was not
// checked. No network calls.
//
// Not checked, and why: NLA/CredSSP and the NTLM host information Nmap's
// rdp-ntlm-info prints need an X.224 connection request, whose first payload
// byte after the TPKT header is 0xE0. The sandbox (GenDec v1.3.0) sends Rhai
// strings as UTF-8, where no single byte above 0x7F can be written.

fn name() {
    "shapo_remote_admin_exposure"
}

fn description() {
    "Report reachable RDP and VNC remote-administration services."
}

fn ports() {
    []
}

fn run() {
    let label = "";
    // The port number counts only when the scan could not name the service.
    let unnamed = service == "" || service == "unknown";
    if service == "rdp" || service == "ms-wbt-server" || (unnamed && port == 3389) {
        label = "RDP";
    } else if service == "vnc" || banner.to_lower().starts_with("rfb ") {
        label = "VNC";
    } else {
        return;
    }

    return #{
        title: "Remote administration service reachable (" + label + ")",
        severity: "LOW",
        summary: "Exposure only: " + label + " answers on port " + port + ". Network-level authentication, encryption and password policy were not checked.",
        evidence: "Port " + port + " open (service: " + service + ")"
    };
}
