// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One anonymous CONNECT at protocol level 4 with a clean session, a fixed
// client id and no username or password flags. Only the CONNACK return code
// is judged: 0 is a finding, any other code is a refusal. Subscribe and
// publish are never sent.
fn name() { "shapo_mqtt_anonymous" }
fn description() { "Detect MQTT brokers that accept an anonymous CONNECT." }
fn ports() { [] }
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "mqtt" || (unnamed && port == 1883)) { return; }
    let reply = probe_send_hex(port, "101100044d5154540402003c0005736861706f", 1500).to_lower();
    if reply.len() != 8 { throw "truncated or oversized MQTT CONNACK"; }
    if reply.sub_string(0, 2) != "20" { throw "MQTT reply is not a CONNACK"; }
    if reply.sub_string(2, 2) != "02" { throw "malformed MQTT CONNACK remaining length"; }
    if reply.sub_string(4, 2) != "00" { throw "MQTT session present is set for a clean-session CONNECT"; }
    if reply.sub_string(6, 2) != "00" { return; }
    return #{title: "MQTT broker accepts anonymous connections", severity: "LOW",
        summary: "The broker answered an anonymous CONNECT (protocol level 4, clean session, fixed client id, no credentials) with CONNACK 0. Subscribe and publish were not attempted.",
        evidence: "An unauthenticated MQTT CONNECT was accepted with return code 0."};
}
