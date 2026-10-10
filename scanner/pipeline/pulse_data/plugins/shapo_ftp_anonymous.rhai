// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
//
// Anonymous FTP login (replaces Nmap's ftp-anon, minus the directory listing:
// a listing needs a second, data connection and the sandbox allows exactly the
// scanned port).
//
// One call, three commands in one write. The server answers them in order and
// closes after QUIT, so the call ends at EOF rather than at the read timeout.
// The login is the evidence: reply code 230. The password is a placeholder.

fn name() {
    "shapo_ftp_anonymous"
}

fn description() {
    "Report FTP servers that accept an anonymous login."
}

fn ports() {
    []
}

fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}

fn run() {
    let greeting = banner.to_lower();
    if !(service == "ftp" || (greeting.starts_with("220") && greeting.contains("ftp"))) {
        return;
    }

    let reply = probe_send(port, "USER anonymous\r\nPASS anonymous@example.invalid\r\nQUIT\r\n", 1500);
    // A failed probe is raised, not swallowed: an empty result would read as
    // "checked, clean" to a verification re-scan (docs/pulse-plugins.md).
    if !reply.starts_with("220") {
        throw "no FTP greeting in the reply: " + head(reply, 60);
    }
    for line in reply.split("\n") {
        if line.starts_with("230") {
            let seen = line;
            seen.trim();
            return #{
                title: "Anonymous FTP login allowed",
                severity: "MEDIUM",
                summary: "The FTP server accepted the user anonymous. Files may be readable, and possibly writable, without credentials; the listing is not checked.",
                evidence: head(seen, 120)
            };
        }
    }
}
