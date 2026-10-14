// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// One SMB1 dialect negotiation; no authentication or exploit payloads.
fn name() { "shapo_smb1" }
fn description() { "Confirm whether the server negotiates the obsolete SMB1 protocol." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "smb" || service == "microsoft-ds" || (unnamed && port == 445)) { return; }
    let reply = probe_send_hex(port, "0000002fff534d4272000000001801280000000000000000000000000000000000000000000c00024e54204c4d20302e313200", 1500).to_lower();
    if reply.len() < 78 || reply.len() % 2 != 0 || !reply.starts_with("00") || reply.sub_string(8, 10) != "ff534d4272" || reply.sub_string(18, 8) != "00000000" { throw "no successful SMB1 negotiation response"; }
    let digits = "0123456789abcdef";
    let size = 0;
    for offset in 2..8 {
        let digit = digits.index_of(reply.sub_string(offset, 1));
        if digit < 0 { throw "invalid SMB1 frame length"; }
        size = size * 16 + digit;
    }
    if (size + 4) * 2 != reply.len() { throw "truncated SMB1 session frame"; }
    let flags = digits.index_of(reply.sub_string(26, 1));
    if flags < 8 { throw "SMB1 packet is not a server response"; }
    if reply.sub_string(72, 6) == "01ffff" { return; }
    if reply.len() < 146 || reply.sub_string(72, 6) != "110000" { throw "invalid SMB1 dialect negotiation response"; }
    return #{ title: "SMB1 protocol is supported", severity: "MEDIUM", summary: "The server selected NT LM 0.12 in response to an SMB1-only NEGOTIATE. Disable the obsolete protocol. Authentication and known SMB exploits were not tested.", evidence: "SMB_COM_NEGOTIATE dialect index 0 (NT LM 0.12)" };
}
