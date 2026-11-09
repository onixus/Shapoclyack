// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Send only the 0-9-1 protocol header and read the answer. A parsed
// connection.start confirms the protocol; no start-ok, credentials, tune,
// open or queue declaration are ever sent, so this is not an anonymous login.
fn name() { "shapo_amqp_start" }
fn description() { "Confirm an AMQP 0-9-1 broker answers the protocol header with connection.start." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated AMQP hex field"; }
    let digits = "0123456789abcdef";
    let hi = digits.index_of(data.sub_string(pos * 2, 1));
    let lo = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if hi < 0 || lo < 0 { throw "invalid hex in AMQP reply"; }
    return hi * 16 + lo;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "amqp" || (unnamed && port == 5672)) { return; }
    let reply = probe_send_hex(port, "414d515000000901", 1500).to_lower();
    if reply.len() < 24 || reply.len() % 2 != 0 || reply.len() > 32768 { throw "truncated AMQP frame"; }
    if octet(reply, 0) != 1 { throw "AMQP reply is not a method frame"; }
    if reply.sub_string(2, 4) != "0000" { throw "AMQP handshake arrived on a non-zero channel"; }
    let size = octet(reply, 3) * 16777216 + octet(reply, 4) * 65536 + octet(reply, 5) * 256 + octet(reply, 6);
    if size < 4 || (size + 8) * 2 != reply.len() { throw "AMQP frame length mismatch"; }
    if reply.sub_string(14, 8) != "000a000a" { throw "AMQP reply is not connection.start"; }
    if octet(reply, size + 7) != 206 { throw "missing AMQP frame end"; }
    return #{title: "AMQP 0-9-1 handshake offered without client credentials", severity: "LOW",
        summary: "The broker answered the 0-9-1 protocol header with a parsed connection.start frame. This confirms the protocol only: no credentials were offered, no start-ok was sent and no login took place. Queues were not declared.",
        evidence: "The broker replied to the protocol header with a connection.start (class 10, method 10) frame."};
}
