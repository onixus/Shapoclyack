// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// SMB2 NEGOTIATE only; no session, authentication or file access.
// SMB1 and the full dialect list are not assessed by this probe.
fn name() { "shapo_smb_signing" }
fn description() { "Observe whether SMB2 negotiation requires message signing." }
fn ports() { [] }
fn byte_at(reply, index) {
    let digits = "0123456789abcdef";
    let hi = digits.index_of(reply.sub_string(index * 2, 1));
    let lo = digits.index_of(reply.sub_string(index * 2 + 1, 1));
    if hi < 0 || lo < 0 { throw "invalid hex in SMB reply"; }
    return hi * 16 + lo;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "smb" || service == "microsoft-ds" || (unnamed && port == 445)) { return; }
    let reply = probe_send_hex(port, "00000068fe534d424000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400020001000000000000000123456789abcdef0123456789abcdef000000000000000002021002", 1500).to_lower();
    if reply.len() < 264 || reply.len() > 131072 || reply.len() % 2 != 0 { throw "truncated or oversized SMB2 negotiate reply"; }
    let size = byte_at(reply, 1) * 65536 + byte_at(reply, 2) * 256 + byte_at(reply, 3);
    if byte_at(reply, 0) != 0 || size < 128 || (size + 4) * 2 != reply.len() { throw "invalid SMB session frame length"; }
    if reply.sub_string(8, 8) != "fe534d42" || reply.sub_string(16, 4) != "4000" || reply.sub_string(24, 8) != "00000000" || reply.sub_string(32, 4) != "0000" || (byte_at(reply, 20) & 1) != 1 || reply.sub_string(56, 16) != "0000000000000000" || reply.sub_string(136, 4) != "4100" { throw "not a successful SMB2 negotiate response"; }
    let dialect = reply.sub_string(144, 4);
    if dialect != "0202" && dialect != "1002" { throw "server selected an unrequested SMB dialect"; }
    let mode = byte_at(reply, 70) + byte_at(reply, 71) * 256;
    if mode > 3 { throw "invalid SMB2 signing mode"; }
    if (mode & 2) == 2 { return; }
    return #{ title: "SMB2 message signing is not required", severity: "MEDIUM", summary: "The SMB2 NEGOTIATE response does not require message signing. Session authentication and relay exploitability were not tested.", evidence: "SMB2 SecurityMode=" + mode + "; selected dialect bytes=" + dialect };
}
