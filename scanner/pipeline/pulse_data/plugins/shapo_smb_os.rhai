// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One SMB1 NEGOTIATE; a Native OS string in the reply means the server answered.
// No session setup, share enumeration or file access is attempted.
fn name() { "shapo_smb_os" }
fn description() { "Detect an SMB1 server that returns Native OS information during negotiate." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated hex data"; }
    let digits = "0123456789abcdef";
    let a = digits.index_of(data.sub_string(pos * 2, 1));
    let b = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if a < 0 || b < 0 { throw "invalid hex data"; }
    return a * 16 + b;
}
fn be16(data, pos) {
    return octet(data, pos) * 256 + octet(data, pos + 1);
}
fn be32(data, pos) {
    return octet(data, pos) * 16777216 + octet(data, pos + 1) * 65536 + octet(data, pos + 2) * 256 + octet(data, pos + 3);
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "smb" || service == "microsoft-ds" || service == "netbios-ssn" || (unnamed && port == 445) || (unnamed && port == 139)) { return; }
    let request = "0000008eff534d4272000000182800000000000000000000000000000000000000000000006b00025043204e4554574f524b2050524f4752414d20312e3000024d4943524f534f4654204e4554574f524b5320312e303300024d4943524f534f4654204e4554574f524b5320332e3000024c414e4d414e312e3000024c4d312e325830303200024e54204c4d20302e313200";
    let reply = probe_send_hex(port, request, 1500).to_lower();
    if reply.len() == 0 { throw "empty SMB1 negotiate reply"; }
    if reply.len() < 140 { throw "truncated SMB1 negotiate reply"; }
    let msg_len = be32(reply, 0);
    if msg_len < 32 || 4 + msg_len != reply.len() / 2 { throw "SMB1 NetBIOS length mismatch"; }
    if reply.sub_string(8, 8) != "ff534d42" { throw "SMB1 magic mismatch"; }
    if octet(reply, 8) != 0x72 { throw "SMB1 reply is not NEGOTIATE"; }
    let word_count = octet(reply, 36);
    if word_count != 17 { throw "SMB1 NEGOTIATE word count mismatch"; }
    let dialect = be16(reply, 37);
    if dialect == 0xffff { throw "SMB1 NEGOTIATE did not select a dialect"; }
    let capabilities = be32(reply, 56);
    if (capabilities & 0x80000000) != 0 { throw "SMB1 NEGOTIATE used extended security, no Native OS returned"; }
    let challenge_len = octet(reply, 70);
    let byte_count = be16(reply, 71);
    if byte_count < challenge_len + 2 { throw "SMB1 NEGOTIATE data too short for Native OS"; }
    let data_start = 73;
    let os_start = data_start + challenge_len;
    let os_end = os_start;
    while os_end < data_start + byte_count {
        if octet(reply, os_end) == 0 { break; }
        os_end += 1;
    }
    if os_end == os_start { throw "SMB1 NEGOTIATE has no Native OS string"; }
    if os_end >= data_start + byte_count { throw "SMB1 NEGOTIATE Native OS string is not null-terminated"; }
    let os_len = os_end - os_start;
    if os_len > 128 { throw "SMB1 NEGOTIATE Native OS string is too long"; }
    for i in 0..os_len {
        let b = octet(reply, os_start + i);
        if b < 0x20 || b > 0x7e { throw "SMB1 NEGOTIATE Native OS string contains non-printable bytes"; }
    }
    return #{
        title: "SMB1 Native OS information disclosed",
        severity: "LOW",
        summary: "An SMB1 NEGOTIATE response contained a Native OS string without authentication. The string value, host name and domain are not copied; shares and files were not accessed.",
        evidence: "SMB1 NEGOTIATE returned a complete Native OS string."
    };
}
