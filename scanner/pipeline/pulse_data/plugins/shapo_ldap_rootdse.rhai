// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// One anonymous SearchRequest against the empty base (RootDSE) asking only
// for supportedLDAPVersion and namingContexts; no Bind is sent. A parsed
// SearchResultEntry is the finding; resultCode 49 (invalidCredentials) and 50
// (insufficientAccessRights) are refusals; every other non-zero code is
// unverified and raises. Attribute values are never copied out.
fn name() { "shapo_ldap_rootdse" }
fn description() { "Detect LDAP directories that answer an anonymous RootDSE search." }
fn ports() { [] }
fn octet(data, pos) {
    if pos < 0 || pos * 2 + 2 > data.len() { throw "truncated LDAP hex field"; }
    let digits = "0123456789abcdef";
    let hi = digits.index_of(data.sub_string(pos * 2, 1));
    let lo = digits.index_of(data.sub_string(pos * 2 + 1, 1));
    if hi < 0 || lo < 0 { throw "invalid hex in LDAP reply"; }
    return hi * 16 + lo;
}
fn ber(data, pos, limit) {
    if pos < 0 || pos * 2 + 4 > data.len() { throw "truncated LDAP BER header"; }
    let tag = octet(data, pos);
    let len = octet(data, pos + 1);
    let start = pos + 2;
    if len == 128 { throw "indefinite LDAP BER length"; }
    if len >= 128 {
        let count = len - 128;
        if count < 1 || count > 4 { throw "unbounded LDAP BER length"; }
        len = 0;
        for i in 0..count { len = len * 256 + octet(data, start + i); }
        start += count;
    }
    let end = start + len;
    if end * 2 > data.len() || end > limit { throw "truncated LDAP BER value"; }
    return [tag, start, end];
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "ldap" || (unnamed && port == 389)) { return; }
    let reply = probe_send_hex(port, "3050020101634b04000a01000a0100020100020100010100a310040b6f626a656374436c61737304012a30260414737570706f727465644c44415056657273696f6e040e6e616d696e67436f6e7465787473", 1500).to_lower();
    if reply.len() < 8 || reply.len() % 2 != 0 || reply.len() > 32768 { throw "invalid LDAP response size"; }
    let limit = reply.len() / 2;
    let pos = 0;
    let saw_entry = false;
    while pos < limit {
        let msg = ber(reply, pos, limit);
        if msg[0] != 48 { throw "LDAP reply is not a closed BER sequence"; }
        let id = ber(reply, msg[1], msg[2]);
        if id[0] != 2 || id[2] != id[1] + 1 || octet(reply, id[1]) != 1 { throw "LDAP message id mismatch"; }
        let op = ber(reply, id[2], msg[2]);
        if op[2] != msg[2] { throw "unexpected trailing fields in LDAP message"; }
        pos = msg[2];
        if op[0] == 100 {
            let dn = ber(reply, op[1], op[2]);
            if dn[0] != 4 || dn[1] != dn[2] { throw "unexpected LDAP RootDSE object name"; }
            let attrs = ber(reply, dn[2], op[2]);
            if attrs[0] != 48 { throw "unexpected LDAP entry attribute list"; }
            let apos = attrs[1];
            while apos < attrs[2] {
                let pa = ber(reply, apos, attrs[2]);
                if pa[0] != 48 { throw "unexpected LDAP partial attribute"; }
                let ptype = ber(reply, pa[1], pa[2]);
                if ptype[0] != 4 { throw "unexpected LDAP attribute type"; }
                let vals = ber(reply, ptype[2], pa[2]);
                if vals[0] != 49 { throw "unexpected LDAP attribute value set"; }
                let vpos = vals[1];
                while vpos < vals[2] {
                    let val = ber(reply, vpos, vals[2]);
                    if val[0] != 4 { throw "unexpected LDAP attribute value"; }
                    vpos = val[2];
                }
                apos = pa[2];
            }
            saw_entry = true;
        } else if op[0] == 101 {
            let code = ber(reply, op[1], op[2]);
            if code[0] != 10 || code[2] != code[1] + 1 { throw "unexpected LDAP result code"; }
            let matched = ber(reply, code[2], op[2]);
            if matched[0] != 4 { throw "unexpected LDAP matched DN"; }
            let diag = ber(reply, matched[2], op[2]);
            if diag[0] != 4 || diag[2] != op[2] { throw "LDAP result done fields overrun"; }
            let rc = octet(reply, code[1]);
            if rc == 0 {
                if !saw_entry { throw "LDAP search succeeded without a RootDSE entry"; }
                return #{title: "LDAP RootDSE searchable without authentication", severity: "LOW",
                    summary: "An anonymous SearchRequest against the empty base returned a parsed SearchResultEntry without a Bind. Directory data access, subtree search and authenticated operations were not tested.",
                    evidence: "The RootDSE search returned a parsed entry with an empty object name; attribute values were not recorded."};
            }
            if rc == 49 || rc == 50 { return; }
            throw "LDAP search returned an unverified result code";
        } else {
            throw "unexpected LDAP protocol op";
        }
    }
    throw "LDAP response ended before SearchResultDone";
}
