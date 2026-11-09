// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One anonymous ApiVersions request (api key 18, api version 0, own
// correlation id, client id shapo). The frame length, the echoed correlation
// id and a zero error code must all match. Topic metadata, produce, fetch and
// any SASL exchange are out of scope for this check.
fn name() { "shapo_kafka_apiversions" }
fn description() { "Detect Kafka brokers that answer ApiVersions without authentication." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated Kafka hex field"; }
    let digits = "0123456789abcdef";
    let hi = digits.index_of(data.sub_string(pos * 2, 1));
    let lo = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if hi < 0 || lo < 0 { throw "invalid hex in Kafka reply"; }
    return hi * 16 + lo;
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "kafka" || (unnamed && port == 9092)) { return; }
    let reply = probe_send_hex(port, "0000000f00120000534841500005736861706f", 1500).to_lower();
    if reply.len() < 20 || reply.len() % 2 != 0 || reply.len() > 32768 { throw "truncated or oversized Kafka reply"; }
    let size = octet(reply, 0) * 16777216 + octet(reply, 1) * 65536 + octet(reply, 2) * 256 + octet(reply, 3);
    if size < 6 || (size + 4) * 2 != reply.len() { throw "Kafka frame length mismatch"; }
    if reply.sub_string(8, 8) != "53484150" { throw "Kafka correlation id mismatch"; }
    // Refusal codes are not verified against the v0 spec yet: a non-zero error
    // code must not read as clean and must not read as a finding.
    if reply.sub_string(16, 4) != "0000" { throw "Kafka ApiVersions returned an unverified non-zero error code"; }
    return #{title: "Kafka ApiVersions answered without authentication", severity: "LOW",
        summary: "An anonymous ApiVersions v0 request was accepted: the response header parsed, the frame length matched, and the error code was 0. Topic metadata, produce and fetch were not attempted.",
        evidence: "The broker accepted an unauthenticated ApiVersions v0 request without a SASL handshake. No topics were read."};
}
