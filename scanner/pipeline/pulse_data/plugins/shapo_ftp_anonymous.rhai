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

// Final lines of an FTP-style reply stream, in order. A reply is "NNN text" or
// a block opened by "NNN-" and closed by "NNN " (lines in between are text,
// whatever they start with: a multi-line greeting can contain "230 "). The
// code is the first three characters of the line.
fn final_lines(reply) {
    let finals = [];
    let open = "";
    for raw in reply.split("\n") {
        let line = raw;
        line.trim();
        if line.len() < 3 {
            continue;
        }
        if open != "" {
            if line.starts_with(open + " ") || line == open {
                finals.push(line);
                open = "";
            }
            continue;
        }
        if line.len() > 3 && line.sub_string(3, 1) == "-" {
            open = line.sub_string(0, 3);
        } else {
            finals.push(line);
        }
    }
    finals
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
    let finals = final_lines(reply);
    if finals.len() < 3 || !finals[0].starts_with("220") {
        throw "no complete FTP reply to USER/PASS: " + head(reply, 60);
    }
    // The answer to PASS decides; a server that logs in on USER alone answers 230 there.
    // 230 inside a multi-line greeting or banner text is not a login.
    // The evidence is that reply's own closing line.
    let decisive = "";
    if finals[1].starts_with("230") {
        decisive = finals[1];
    } else if finals[2].starts_with("230") {
        decisive = finals[2];
    }
    if decisive != "" {
        return #{
            title: "Anonymous FTP login allowed",
            severity: "MEDIUM",
            summary: "The FTP server accepted the user anonymous. Files may be readable, and possibly writable, without credentials; the listing is not checked.",
            evidence: head(decisive, 120)
        };
    }
}
