// SPDX-License-Identifier: MIT
// Copyright (c) onixus
//
// Derived from GenDec scripts/ssh_audit.rhai (GenDec v1.3.0, MIT; the
// Cargo.toml `license` field is the licence statement of that release).
// Changes for Shapoclyack: runs on any port whose service is SSH, not on
// 22/2222 only; separates "protocol 1 only" (SSH-1.5) from "protocol 1
// compatible" (SSH-1.99); reads the OpenSSH major version instead of matching
// a list of prefixes; severities and wording adjusted. No network calls.

fn name() {
    "shapo_ssh_banner"
}

fn description() {
    "Report SSH protocol 1 and end-of-life OpenSSH releases disclosed in the banner."
}

fn ports() {
    []
}

fn openssh_major(text) {
    let at = text.index_of("OpenSSH_");
    if at < 0 {
        return -1;
    }
    let rest = text.sub_string(at + 8);
    let digits = "";
    for ch in rest.chars() {
        if ch >= '0' && ch <= '9' {
            digits += ch;
        } else {
            break;
        }
    }
    if digits.len() == 0 {
        return -1;
    }
    parse_int(digits)
}

fn run() {
    if !(service == "ssh" || banner.to_lower().starts_with("ssh-")) {
        return;
    }

    if banner.starts_with("SSH-1.5") {
        return #{
            title: "SSH protocol 1 only",
            severity: "HIGH",
            summary: "The server identifies as SSH protocol 1.5, a protocol with known cryptographic weaknesses that no current client should speak.",
            evidence: banner
        };
    }
    if banner.starts_with("SSH-1.99") {
        return #{
            title: "SSH protocol 1 compatibility advertised",
            severity: "MEDIUM",
            summary: "The server identifies as SSH-1.99, meaning it still accepts protocol 1 connections.",
            evidence: banner
        };
    }

    let major = openssh_major(banner);
    if major >= 0 && major < 7 {
        return #{
            title: "Old OpenSSH release",
            severity: "LOW",
            summary: "The banner says OpenSSH " + major + ".x, which predates 7.0 and is out of upstream support. Distributions backport fixes without changing this string, so it is a hint to check the package, not proof of exposure.",
            evidence: banner
        };
    }
}
