// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// Separate assessment identity: other SMB observations cannot close this check.
// Anonymous IPC$ PeekNamedPipe FID0 only; no exploit, file write or credentials.
fn name() { "shapo_ms17_010" }
fn description() { "Observe the read-only SMB MS17-010 status indication without asserting patch status." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "smb" || service == "microsoft-ds" || service == "netbios-ssn" || (unnamed && port == 445) || (unnamed && port == 139)) { return; }
    let netbios = service == "netbios-ssn" || port == 139;
    let result = probe_ms17_010(port, netbios, 5000);
    if result.contains("error") { throw "MS17-010 assessment unknown: " + result.error; }
    if !result.status.starts_with("ms17_010_status_indicator:") { throw "MS17-010 assessment unknown (no patch attestation): " + result.status; }
    return #{title: "SMB MS17-010 status indication observed", severity: "HIGH", confidence: 82, requires_confirmation: true, summary: "An anonymous IPC$ PeekNamedPipe transaction on FID0 returned STATUS_INSUFF_SERVER_RESOURCES. This is the MS17-010 diagnostic indication; exploitability and patch installation were not authenticated or tested.", evidence: "SMB_COM_TRANSACTION FID0 PeekNamedPipe=" + result.status};
}
