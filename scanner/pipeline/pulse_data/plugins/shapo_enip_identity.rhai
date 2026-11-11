// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One EtherNet/IP List Identity (encapsulation command 0x0063) with no
// registered session. The reply must echo the command, close its declared
// encapsulation length against the frame, report a zero command status and
// carry exactly one identity item (type 0x0c) whose length also closes.
// A non-zero command status is a refusal. Register Session, SendRRData and
// CIP attribute writes are never sent; the product name, serial number and
// socket address inside the identity data are never copied out.
fn name() { "shapo_enip_identity" }
fn description() { "Detect EtherNet/IP devices that answer List Identity without a session." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated EtherNet/IP hex field"; }
    let digits = "0123456789abcdef";
    let hi = digits.index_of(data.sub_string(pos * 2, 1));
    let lo = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if hi < 0 || lo < 0 { throw "invalid hex in EtherNet/IP reply"; }
    return hi * 16 + lo;
}
fn le16(data, pos) {
    return octet(data, pos) + octet(data, pos + 1) * 256;
}
fn le32(data, pos) {
    return octet(data, pos) + octet(data, pos + 1) * 256 + octet(data, pos + 2) * 65536 + octet(data, pos + 3) * 16777216;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "enip" || (unnamed && port == 44818)) { return; }
    // List Identity: 24-byte encapsulation header. Command 0x0063, length 0,
    // session 0, status 0, sender context 0, options 0.
    let reply = probe_send_hex(port, "630000000000000000000000000000000000000000000000", 1500).to_lower();
    if reply.len() == 0 { throw "empty EtherNet/IP List Identity reply"; }
    if reply.len() < 48 || reply.len() % 2 != 0 { throw "truncated EtherNet/IP encapsulation header"; }
    if le16(reply, 0) != 0x63 { throw "EtherNet/IP reply command is not List Identity"; }
    let data_len = le16(reply, 2);
    if 24 + data_len != reply.len() / 2 { throw "EtherNet/IP encapsulation length mismatch"; }
    if le32(reply, 8) != 0 { return; }
    if data_len < 6 { throw "EtherNet/IP identity list is too short for one item"; }
    if le16(reply, 24) != 1 { throw "EtherNet/IP reply does not carry exactly one item"; }
    if le16(reply, 26) != 0x0c { throw "EtherNet/IP item is not an identity item"; }
    let item_len = le16(reply, 28);
    if item_len < 1 || 30 + item_len != 24 + data_len { throw "EtherNet/IP identity item length mismatch"; }
    return #{
        title: "EtherNet/IP List Identity answered without a session",
        severity: "LOW",
        summary: "A single List Identity command (0x0063) returned a parsed identity item: the encapsulation length and the item length both close and the command status is zero. No session was registered and no CIP object was read or written.",
        evidence: "The device answered an unregistered List Identity request with one complete identity item. The product name, serial number and socket address inside the item were not recorded."
    };
}
