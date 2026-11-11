// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Two steps on one socket: AUTHENTICATE NTLM, then a minimal NTLM type1 token
// (no workstation name) on the continuation. A parsed type2 challenge confirms
// the mechanism. No type3, credentials or LOGIN are ever sent.
fn name() { "shapo_imap_ntlm" }
fn description() { "Observe whether an IMAP server answers AUTHENTICATE NTLM with a parsed NTLM type2 challenge." }
fn ports() { [] }

// One byte of a lowercase hex string.
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated NTLM hex field"; }
    let digits = "0123456789abcdef";
    let hi = digits.index_of(data.sub_string(pos * 2, 1));
    let lo = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if hi < 0 || lo < 0 { throw "invalid hex in NTLM reply"; }
    hi * 16 + lo
}

// Base64 alphabet value of a byte; -1 outside the alphabet.
fn b64_value(byte) {
    if byte >= 65 && byte <= 90 { return byte - 65; }
    if byte >= 97 && byte <= 122 { return byte - 71; }
    if byte >= 48 && byte <= 57 { return byte + 4; }
    if byte == 43 { return 62; }
    if byte == 47 { return 63; }
    -1
}

// Decode the base64 continuation payload (as hex of its ASCII bytes) into the
// hex of the decoded bytes. "" when the payload is not well-formed base64:
// such a continuation is not an NTLM type2.
fn b64_decode(payload) {
    let count = payload.len() / 2;
    if payload.len() == 0 || payload.len() % 2 != 0 || count % 4 != 0 { return ""; }
    let digits = "0123456789abcdef";
    let out = "";
    let i = 0;
    while i < count {
        let n = 0;
        let pad = 0;
        let k = 0;
        while k < 4 {
            let byte = octet(payload, i + k);
            if byte == 61 {
                pad += 1;
                n *= 64;
            } else {
                if pad > 0 { return ""; }
                let v = b64_value(byte);
                if v < 0 { return ""; }
                n = n * 64 + v;
            }
            k += 1;
        }
        if pad > 2 { return ""; }
        if pad > 0 && i + 4 < count { return ""; }
        let b0 = n / 65536;
        let b1 = n / 256 % 256;
        let b2 = n % 256;
        out += digits.sub_string(b0 / 16, 1) + digits.sub_string(b0 % 16, 1);
        if pad < 2 {
            out += digits.sub_string(b1 / 16, 1) + digits.sub_string(b1 % 16, 1);
        }
        if pad < 1 {
            out += digits.sub_string(b2 / 16, 1) + digits.sub_string(b2 % 16, 1);
        }
        i += 4;
    }
    out
}

fn run() {
    if !(service == "imap") { return; }
    let reply = probe_send(port, "a001 AUTHENTICATE NTLM\r\n", 1500);
    if reply.len() == 0 { throw "empty IMAP reply"; }
    let proceed = false;
    for raw in reply.split("\n") {
        let line = raw;
        line.trim();
        if line.starts_with("+") { proceed = true; break; }
        if line.starts_with("a001 NO") || line.starts_with("a001 BAD") { return; }
    }
    if !proceed { throw "no continuation or refusal answered AUTHENTICATE NTLM"; }
    // The minimal type1: signature, message type 1, flags, empty security
    // buffers, no workstation name, no version, no type3.
    let hexed = probe_send_hex(port, "4e544c4d53535000010000000782080000000000000000000000000000000000", 1500).to_lower();
    if hexed.len() == 0 { throw "empty reply to the NTLM type1"; }
    if hexed.starts_with("2a20") {
        throw "blocked: the second probe_send opened a new connection (the server re-greeted), so AUTHENTICATE NTLM cannot complete on one socket";
    }
    if !(hexed.len() >= 2 && hexed.sub_string(0, 2) == "2b") {
        if hexed.starts_with("61303031204e4f") || hexed.starts_with("6130303120424144") { return; }
        throw "unexpected reply to the NTLM type1";
    }
    // "+ <base64 type2>\r\n": the payload ends at the first byte that is not
    // base64, the CR or LF of the line. Bytes are checked by value: a hex
    // substring search could see "0a" inside the base64 text ('0' and 'a' are
    // both alphabet bytes).
    let at = if hexed.len() >= 4 && hexed.sub_string(2, 2) == "20" { 4 } else { 2 };
    let p = at / 2;
    while p * 2 + 2 <= hexed.len() {
        let byte = octet(hexed, p);
        if b64_value(byte) < 0 && byte != 61 { break; }
        p += 1;
    }
    let payload = if p * 2 > at { hexed.sub_string(at, p * 2 - at) } else { "" };
    if payload.len() == 0 { return; }
    let t2 = b64_decode(payload);
    if t2.len() == 0 { return; }
    if t2.len() < 16 || t2.sub_string(0, 16) != "4e544c4d53535000" { return; }
    if t2.len() < 24 { throw "truncated NTLM message after the signature"; }
    if t2.sub_string(16, 8) != "02000000" { return; }
    if t2.len() < 64 { throw "truncated NTLM type2 challenge"; }
    let frame = t2.len() / 2;
    let tlen = octet(t2, 12) + octet(t2, 13) * 256;
    let toff = octet(t2, 16) + octet(t2, 17) * 256 + octet(t2, 18) * 65536 + octet(t2, 19) * 16777216;
    if tlen > 0 && toff + tlen > frame { throw "type2 target name block exceeds the frame"; }
    if t2.len() >= 104 {
        let ilen = octet(t2, 44) + octet(t2, 45) * 256;
        let ioff = octet(t2, 48) + octet(t2, 49) * 256 + octet(t2, 50) * 65536 + octet(t2, 51) * 16777216;
        if ilen > 0 && ioff + ilen > frame { throw "type2 target info block exceeds the frame"; }
    }
    return #{
        title: "IMAP NTLM authentication answered with a type2 challenge",
        severity: "LOW",
        summary: "The server accepted AUTHENTICATE NTLM and answered the minimal type1 token with a parsed NTLM type2 challenge. No credentials, LOGIN, PLAIN or NTLM type3 were sent; the challenge contents were not recorded.",
        evidence: "AUTHENTICATE NTLM continuation carried a parsed NTLM type2 challenge (signature NTLMSSP, message type 2, block lengths within the frame). Host name, domain and timestamp were not recorded."
    };
}
