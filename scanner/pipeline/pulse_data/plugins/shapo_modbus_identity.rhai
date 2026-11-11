// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One Modbus read-device-identification request (function 43/14/01).
// No register write is performed.
fn name() { "shapo_modbus_identity" }
fn description() { "Detect a Modbus TCP device answering a read-device-identification request." }
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
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "modbus" || (unnamed && port == 502)) { return; }
    let reply = probe_send_hex(port, "000100000004002b0e01", 1500).to_lower();
    if reply.len() == 0 { throw "empty Modbus reply"; }
    if reply.len() < 18 { throw "truncated Modbus reply"; }
    let trans = be16(reply, 0);
    if trans != 1 { throw "Modbus transaction id mismatch"; }
    if be16(reply, 2) != 0 { throw "Modbus protocol id mismatch"; }
    let length = be16(reply, 4);
    if length < 3 || 6 + length > reply.len() / 2 { throw "Modbus length mismatch"; }
    let unit = octet(reply, 6);
    let func = octet(reply, 7);
    if func == 0x2b {
        if octet(reply, 8) != 0x0e { throw "Modbus MEI type mismatch"; }
        return #{
            title: "Modbus device identification answered",
            severity: "LOW",
            summary: "The Modbus server returned a read-device-identification response. Registers were not read or written.",
            evidence: "Modbus function 43 read-device-identification returned a complete reply."
        };
    }
    if func == 0xab {
        if length >= 3 && octet(reply, 8) == 0x0e { return; }
        throw "Modbus exception with unexpected code";
    }
    throw "unexpected Modbus function code";
}
