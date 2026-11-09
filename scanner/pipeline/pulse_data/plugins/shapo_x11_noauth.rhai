// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Confirms: the display accepts a little-endian X11 11.0 connection setup
// that names no authorization protocol. Not checked: any request after the
// accepted setup, xhost state, screen contents, input and window listings.
fn name() { "shapo_x11_noauth" }
fn description() { "Detect an X11 display accepting a connection setup without authorization." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated X11 field"; }
    let digits = "0123456789abcdef";
    let a = digits.index_of(data.sub_string(pos * 2, 1));
    let b = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if a < 0 || b < 0 { throw "invalid X11 hex"; }
    return a * 16 + b;
}
fn u16le(data, pos) {
    return octet(data, pos) + octet(data, pos + 1) * 256;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "x11" || (unnamed && port == 6000) || (unnamed && port == 6001) || (unnamed && port == 6002) || (unnamed && port == 6003) || (unnamed && port == 6004) || (unnamed && port == 6005)) { return; }
    let reply = probe_send_hex(port, "6c000b000000000000000000", 1500).to_lower();
    if reply.len() == 0 { throw "empty X11 connection-setup reply"; }
    if reply.len() < 16 { throw "truncated X11 connection-setup reply"; }
    let status = reply.sub_string(0, 2);
    let extra = u16le(reply, 6);
    if reply.len() != 16 + extra * 8 { throw "inconsistent X11 reply length"; }
    if status == "01" {
        return #{
            title: "X11 display accepts a connection setup without authorization",
            severity: "MEDIUM",
            summary: "The server accepted an X11 connection setup with an empty authorization name and data. No request after the setup was sent, so screen contents, input and window listings were not read.",
            evidence: "A little-endian X11 11.0 connection setup with zero-length authorization name and data was accepted."
        };
    }
    if status == "00" {
        let reason = octet(reply, 1);
        if reason > extra * 4 { throw "inconsistent X11 refusal reason length"; }
        return;
    }
    throw "unexpected X11 connection-setup status byte: " + status;
}
