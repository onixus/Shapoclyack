// SPDX-License-Identifier: MIT
// Copyright (c) onixus
//
// Derived from GenDec scripts/smb_netbios_exposure_audit.rhai (GenDec v1.3.0,
// MIT; the Cargo.toml `license` field is the licence statement of that
// release). Changes for Shapoclyack: matches on the detected service as well
// as the port; HIGH lowered to MEDIUM because the finding is reachability
// only; the summary says what was not checked. No network calls.
//
// Not checked, and why: SMB signing, SMBv1 and the dialect list need an SMB
// negotiate packet. It starts with the byte 0xFE or 0xFF, and the sandbox
// (GenDec v1.3.0) sends Rhai strings as UTF-8, where no single byte above 0x7F
// can be written. Nmap's smb2-security-mode and smb-security-mode therefore
// have no equivalent here.

fn name() {
    "shapo_smb_exposure"
}

fn description() {
    "Report reachable SMB and NetBIOS session services."
}

fn ports() {
    []
}

fn run() {
    let label = "";
    if service == "smb" || service == "microsoft-ds" || port == 445 {
        label = "SMB";
    } else if service == "netbios-ssn" || port == 139 {
        label = "NetBIOS session";
    } else {
        return;
    }

    return #{
        title: "SMB / NetBIOS service reachable (" + label + ")",
        severity: "MEDIUM",
        summary: "A file-sharing service (" + label + ") answers on port " + port + ". Reachability only: message signing, SMBv1 and the dialect list were not checked.",
        evidence: "Port " + port + " open (service: " + service + ")"
    };
}
