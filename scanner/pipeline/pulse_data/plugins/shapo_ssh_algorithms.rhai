// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
//
// Weak SSH key-exchange, host-key, cipher and MAC algorithms (replaces the
// weakness half of Nmap's ssh2-enum-algos; docs/pulse-plugins.md).
//
// One call: send our identification line and then bytes that are not a valid
// binary packet, so the server (which has already queued its KEXINIT) answers
// with it and drops the connection instead of waiting out the read timeout.
// The sandbox hands the reply back through from_utf8_lossy with control
// characters turned into '.', so the length prefixes of the name-lists are
// unreadable and the lists cannot be split by position. They are split by what
// survives: ',' between names, and a run of two or more dots (a sanitised
// length prefix) between lists. The one garbage character a prefix can leave
// glued to the front of a list is tolerated when matching.
//
// What this cannot do (sandbox, GenDec v1.3.0): ssh-hostkey needs the key
// exchange itself, which is a binary protocol.

fn name() {
    "shapo_ssh_algorithms"
}

fn description() {
    "Report weak SSH key-exchange, host-key, cipher and MAC algorithms offered in KEXINIT."
}

fn ports() {
    []
}

// Broken or removed from current guidance: MEDIUM.
fn broken_algorithms() {
    [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
        "ssh-dss",
        "ssh-dss-cert-v01@openssh.com",
        "3des-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "rijndael-cbc@lysator.liu.se",
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1-96",
    ]
}

// Deprecated but still common: LOW.
fn deprecated_algorithms() {
    [
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "diffie-hellman-group14-sha1",
    ]
}

fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}

fn algorithm_tokens(raw) {
    let nl = raw.index_of('\n');
    let body = if nl >= 0 { raw.sub_string(nl + 1) } else { raw };
    body.replace("..", ",");
    body.replace("\r", ",");
    body.replace("\n", ",");
    let tokens = [];
    for token in body.split(",") {
        // A three-dot prefix leaves one dot behind the replacement above.
        // Names never start with '.', so any leading dots are prefix residue.
        let name = token;
        while name.starts_with(".") {
            name = name.sub_string(1);
        }
        tokens.push(name);
    }
    tokens
}

fn offers(tokens, wanted) {
    let width = wanted.len();
    for token in tokens {
        let n = token.len();
        if n == width && token == wanted {
            return true;
        }
        // A list's first name may carry one leftover character of the
        // sanitised length prefix in front of it.
        if n == width + 1 && token.ends_with(wanted) {
            return true;
        }
    }
    false
}

fn found_in(tokens, candidates) {
    let found = [];
    for candidate in candidates {
        if offers(tokens, candidate) {
            found.push(candidate);
        }
    }
    found
}

fn join_names(items) {
    let out = "";
    for item in items {
        if out.len() > 0 {
            out += ", ";
        }
        out += item;
    }
    out
}

fn run() {
    if !(service == "ssh" || banner.to_lower().starts_with("ssh-")) {
        return;
    }

    let reply = probe_send(port, "SSH-2.0-shapoclyack_audit\r\n\r\n\r\n\r\n", 1500);
    // A failed probe is raised, not swallowed: an empty result would read as
    // "checked, clean" to a verification re-scan (docs/pulse-plugins.md).
    if !reply.starts_with("SSH-") {
        throw "no SSH identification in the reply: " + head(reply, 60);
    }
    let tokens = algorithm_tokens(reply);
    if tokens.len() < 8 {
        throw "the server closed before sending its algorithm lists";
    }

    let broken = found_in(tokens, broken_algorithms());
    let deprecated = found_in(tokens, deprecated_algorithms());
    if offers(tokens, "ssh-rsa") && !offers(tokens, "rsa-sha2-256") && !offers(tokens, "rsa-sha2-512") {
        deprecated.push("ssh-rsa (SHA-1 signatures only)");
    }
    if broken.len() == 0 && deprecated.len() == 0 {
        return;
    }

    let evidence = "";
    if broken.len() > 0 {
        evidence += "broken: " + join_names(broken);
    }
    if deprecated.len() > 0 {
        if evidence.len() > 0 {
            evidence += "; ";
        }
        evidence += "deprecated: " + join_names(deprecated);
    }

    return #{
        title: "SSH server offers weak algorithms",
        severity: if broken.len() > 0 { "MEDIUM" } else { "LOW" },
        summary: "The SSH server advertises key-exchange, host-key, cipher or MAC algorithms that current guidance has dropped or deprecated.",
        evidence: evidence
    };
}
