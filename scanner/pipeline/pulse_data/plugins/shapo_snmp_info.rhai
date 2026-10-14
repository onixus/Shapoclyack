// SPDX-License-Identifier: Apache-2.0
// Copyright (c) onixus
// One read-only SNMPv2c GET using public; no community guessing or SET.
fn name() { "shapo_snmp_info" }
fn description() { "Read sysDescr and sysName as informational SNMP observations." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated SNMP BER"; }
    let digits = "0123456789abcdef";
    let a = digits.index_of(data.sub_string(pos * 2, 1));
    let b = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if a < 0 || b < 0 { throw "invalid SNMP hex"; }
    return a * 16 + b;
}
fn tlv(data, pos, expected) {
    if octet(data, pos) != expected { throw "unexpected SNMP BER tag"; }
    let len = octet(data, pos + 1);
    let start = pos + 2;
    if len >= 128 {
        let count = len - 128;
        if count < 1 || count > 2 { throw "unbounded SNMP BER length"; }
        len = 0;
        for i in 0..count { len = len * 256 + octet(data, start + i); }
        start += count;
    }
    let end = start + len;
    if end * 2 > data.len() { throw "truncated SNMP BER value"; }
    return [start, end];
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "snmp" || (unnamed && port == 161)) { return; }
    if protocol != "udp" { return; }
    let reply = probe_udp_hex(port, "303502010104067075626c6963a028020453484150020100020100301a300b06072b0601020101000500300b06072b0601020105000500", 1500).to_lower();
    if reply.len() % 2 != 0 || reply.len() > 32768 { throw "invalid SNMP response size"; }
    let msg = tlv(reply, 0, 48);
    if msg[1] * 2 != reply.len() { throw "trailing SNMP response bytes"; }
    let version = tlv(reply, msg[0], 2);
    if reply.sub_string(version[0] * 2, (version[1] - version[0]) * 2) != "01" { throw "unexpected SNMP version"; }
    let community = tlv(reply, version[1], 4);
    if reply.sub_string(community[0] * 2, (community[1] - community[0]) * 2) != "7075626c6963" { throw "SNMP community mismatch"; }
    let pdu = tlv(reply, community[1], 162);
    if pdu[1] != msg[1] { throw "SNMP message boundary mismatch"; }
    let id = tlv(reply, pdu[0], 2);
    if reply.sub_string(id[0] * 2, (id[1] - id[0]) * 2) != "53484150" { throw "SNMP request id mismatch"; }
    let status = tlv(reply, id[1], 2);
    let index = tlv(reply, status[1], 2);
    if reply.sub_string(status[0] * 2, (status[1] - status[0]) * 2) != "00" || reply.sub_string(index[0] * 2, (index[1] - index[0]) * 2) != "00" { throw "SNMP agent refused informational GET"; }
    let vars = tlv(reply, index[1], 48);
    if vars[1] != pdu[1] { throw "SNMP PDU boundary mismatch"; }
    let pos = vars[0];
    let evidence = "";
    for wanted in ["2b060102010100", "2b060102010500"] {
        let item = tlv(reply, pos, 48);
        if item[1] > vars[1] { throw "SNMP varbind escapes list"; }
        let oid = tlv(reply, item[0], 6);
        if reply.sub_string(oid[0] * 2, (oid[1] - oid[0]) * 2) != wanted { throw "unexpected SNMP OID"; }
        // Exceptions (noSuchObject/noSuchInstance) are UNKNOWN, never clean observations.
        let value = tlv(reply, oid[1], 4);
        if value[1] != item[1] || value[1] - value[0] > 1024 { throw "invalid SNMP informational value"; }
        evidence += wanted + "=" + reply.sub_string(value[0] * 2, (value[1] - value[0]) * 2) + ";";
        pos = item[1];
    }
    if pos != vars[1] { throw "unexpected extra SNMP varbind"; }
    return #{title: "SNMP system information observed", severity: "INFO", summary: "sysDescr.0 and sysName.0 returned by one SNMPv2c public-community GET. Read-only protocol observation, not a vulnerability or authenticated asset identity.", evidence: evidence};
}
