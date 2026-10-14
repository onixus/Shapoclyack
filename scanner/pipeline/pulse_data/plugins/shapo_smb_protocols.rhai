// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// Native bounded negotiation + anonymous IPC$ FID0 PeekNamedPipe status check.
// No file writes, exploit, credentials, or patch attestation.
fn name() { "shapo_smb_protocols" }
fn description() { "Observe SMB dialects/signing and the read-only MS17-010 status indication." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "smb" || service == "microsoft-ds" || service == "netbios-ssn" || (unnamed && port == 445) || (unnamed && port == 139)) { return; }
    let netbios = service == "netbios-ssn" || port == 139;
    let result = probe_smb(port, netbios, 1500);
    if result.contains("error") { throw result.error; }
    if result.dialects.len() == 0 { throw "SMB assessment inconclusive: " + result.errors; }
    let evidence = "observed dialects=" + result.dialects + "; SMB2 signing=" + result.signing_modes;
    if result.contains("smb1_signing_required") { evidence += "; SMB1 signing_required=" + result.smb1_signing_required; }
    if result.contains("signing_not_required") || (result.contains("smb1_signing_required") && !result.smb1_signing_required) {
        return #{title: "SMB message signing is not required", severity: "MEDIUM", summary: "At least one observed SMB negotiation does not require message signing. Dialects and partial assessment errors are retained; relay exploitability was not tested.", evidence: evidence, assessment_errors: result.errors};
    }
    return #{title: "SMB dialect inventory observed", severity: "INFO", summary: "Only explicitly selected dialects are listed. MS17-010 is a separate assessment; this inventory gives no vulnerability or patch attestation.", evidence: evidence, assessment_errors: result.errors};
}
