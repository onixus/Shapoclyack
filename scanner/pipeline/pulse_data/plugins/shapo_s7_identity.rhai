// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// COTP connect, then one ReadSZL module-identification request. Identification
// only: no merkers, no outputs, no writes, no CPU state, no rack/slot walk.
fn name() { "shapo_s7_identity" }
fn description() { "Observe whether an S7 PLC answers an unauthenticated SZL module-identification request." }
fn ports() { [] }

fn hexbyte(text, offset) {
    let digits = "0123456789abcdef";
    let hi = digits.index_of(text.sub_string(offset, 1));
    let lo = digits.index_of(text.sub_string(offset + 1, 1));
    if hi < 0 || lo < 0 { throw "reply is not hex"; }
    hi * 16 + lo
}

fn hexword(text, offset) { hexbyte(text, offset) * 256 + hexbyte(text, offset + 2) }

fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "s7" || (unnamed && port == 102)) { return; }

    let confirmed = probe_send_hex(port, "0300001611e00000000100c00109c1020100c2020101", 1500).to_lower();
    if confirmed.len() == 0 { throw "empty reply to the COTP connection request"; }
    if confirmed.len() < 12 || confirmed.len() % 2 != 0 || !confirmed.starts_with("0300") {
        throw "no TPKT/COTP reply to the connection request";
    }
    if hexword(confirmed, 4) * 2 != confirmed.len() { throw "TPKT length does not match the COTP reply"; }
    if hexbyte(confirmed, 10) != 208 { return; }

    let reply = probe_send_hex(port, "0300002002f080320100000000000e00000401120a10020001000100000300c0", 1500).to_lower();
    if reply.len() == 0 { throw "empty reply to the SZL identification request"; }
    if reply.len() < 38 || reply.len() % 2 != 0 || !reply.starts_with("0300") {
        throw "no TPKT/COTP/S7 reply to the SZL identification request";
    }
    if hexword(reply, 4) * 2 != reply.len() { throw "TPKT length does not match the SZL reply"; }
    if reply.sub_string(8, 6) != "02f080" { throw "no COTP data frame in the SZL reply"; }
    if hexbyte(reply, 14) != 50 || hexbyte(reply, 16) != 3 { throw "no S7 Ack_Data reply to the SZL request"; }
    if hexbyte(reply, 34) != 0 || hexbyte(reply, 36) != 0 { return; }
    let param_len = hexword(reply, 26);
    let data_len = hexword(reply, 30);
    let data_at = 38 + param_len * 2;
    if data_len < 4 || data_at + 8 > reply.len() || data_at + data_len * 2 > reply.len() {
        throw "truncated SZL data in the reply";
    }
    if hexbyte(reply, data_at) != 255 { return; }
    if hexword(reply, data_at + 4) + 4 > data_len { throw "SZL block length does not fit the reply"; }
    return #{ title: "S7 module identification answered", severity: "LOW", summary: "The PLC completed a COTP connection and answered an unauthenticated SZL module-identification request. Order number, serial number and station name are not recorded. Memory areas, outputs and CPU state were not accessed.", evidence: "COTP Connection Confirm followed by a ReadSZL Ack_Data with a consistent SZL block length" };
}
