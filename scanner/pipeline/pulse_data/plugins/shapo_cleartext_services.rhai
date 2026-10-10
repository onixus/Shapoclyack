// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
//
// Mail, file-transfer and remote-login services that cannot upgrade to TLS
// (a cleartext-credentials check no Nmap default/safe script made; the Telnet
// part is the same idea as GenDec's ftp_telnet_cleartext_audit).
//
// Telnet needs no probe. FTP, POP3, IMAP and SMTP are asked for their
// capability list and the session is closed in the same write, so the call
// ends at EOF. A server that advertises STARTTLS/STLS/AUTH TLS is not reported
// here: offering TLS is not the same as requiring it, but this check cannot
// tell the two apart without trying a login.

fn name() {
    "shapo_cleartext_services"
}

fn description() {
    "Report Telnet, FTP, POP3, IMAP and SMTP services that offer no way to start TLS."
}

fn ports() {
    []
}

fn kind_of(svc, greeting, number) {
    let g = greeting.to_lower();
    if svc == "telnet" || ((svc == "" || svc == "unknown") && number == 23) {
        return "telnet";
    }
    if svc == "ftp" || (g.starts_with("220") && g.contains("ftp")) {
        return "ftp";
    }
    if svc == "pop3" || g.starts_with("+ok") {
        return "pop3";
    }
    if svc == "imap" || g.starts_with("* ok") {
        return "imap";
    }
    if svc == "smtp" || (g.starts_with("220") && g.contains("smtp")) {
        return "smtp";
    }
    ""
}

// Final reply codes of an FTP/SMTP-style reply stream, in order. A reply is
// "NNN text" or a block opened by "NNN-" and closed by "NNN " (lines in between
// are text, whatever they start with: a multi-line greeting can contain "230 ").
fn final_codes(reply) {
    let codes = [];
    let open = "";
    for raw in reply.split("\n") {
        let line = raw;
        line.trim();
        if line.len() < 3 {
            continue;
        }
        if open != "" {
            if line.starts_with(open + " ") || line == open {
                codes.push(open);
                open = "";
            }
            continue;
        }
        let code = line.sub_string(0, 3);
        if line.len() > 3 && line.sub_string(3, 1) == "-" {
            open = code;
        } else {
            codes.push(code);
        }
    }
    codes
}

fn clip(text, limit) {
    let one_line = text;
    one_line.replace("\r", "");
    one_line.replace("\n", " | ");
    if one_line.len() > limit { one_line.sub_string(0, limit) } else { one_line }
}

// The command must have been accepted before its capability list means anything:
// a refusal (Postfix's pipelining guard answers 554, an FTP server that wants
// TLS first answers FEAT with 530) lists no STARTTLS because it lists nothing.
// A failed probe is raised, not swallowed: an empty result would read as
// "checked, clean" to a verification re-scan (docs/pulse-plugins.md).
fn refused(what, reply) {
    throw what + " did not accept the capability command: " + clip(reply, 60);
}

fn expect(reply, prefix, what) {
    if !reply.starts_with(prefix) {
        throw "no " + what + " greeting in the reply: " + clip(reply, 60);
    }
}

fn run() {
    let kind = kind_of(service, banner, port);
    if kind == "" {
        return;
    }

    if kind == "telnet" {
        return #{
            title: "Telnet service exposed",
            severity: "HIGH",
            summary: "Telnet sends the login and every command in cleartext and has no TLS mode.",
            evidence: "Telnet service on port " + port
        };
    }

    if kind == "ftp" {
        let reply = probe_send(port, "FEAT\r\nQUIT\r\n", 1500);
        expect(reply, "220", "FTP");
        let codes = final_codes(reply);
        if codes.len() < 2 || codes[1] != "211" {
            refused("FTP FEAT", reply);
        }
        let upper = reply.to_upper();
        if upper.contains("AUTH TLS") || upper.contains("AUTH SSL") {
            return;
        }
        return #{
            title: "FTP without TLS",
            severity: "MEDIUM",
            summary: "The FTP server does not advertise AUTH TLS, so logins and files travel in cleartext.",
            evidence: clip(reply, 160)
        };
    }

    if kind == "pop3" {
        let reply = probe_send(port, "CAPA\r\nQUIT\r\n", 1500);
        expect(reply, "+OK", "POP3");
        // Line 1 is the greeting; the answer to CAPA is the next line.
        let lines = reply.split("\n");
        if lines.len() < 2 || !lines[1].starts_with("+OK") {
            refused("POP3 CAPA", reply);
        }
        if reply.to_upper().contains("STLS") {
            return;
        }
        return #{
            title: "POP3 without STLS",
            severity: "MEDIUM",
            summary: "The POP3 server does not advertise STLS, so mailbox passwords and mail travel in cleartext.",
            evidence: clip(reply, 160)
        };
    }

    if kind == "imap" {
        let reply = probe_send(port, "a1 CAPABILITY\r\na2 LOGOUT\r\n", 1500);
        expect(reply, "* OK", "IMAP");
        if !reply.contains("\na1 OK") {
            refused("IMAP CAPABILITY", reply);
        }
        if reply.to_upper().contains("STARTTLS") {
            return;
        }
        return #{
            title: "IMAP without STARTTLS",
            severity: "MEDIUM",
            summary: "The IMAP server does not advertise STARTTLS, so mailbox passwords and mail travel in cleartext.",
            evidence: clip(reply, 160)
        };
    }

    // smtp
    let reply = probe_send(port, "EHLO shapoclyack.invalid\r\nQUIT\r\n", 1500);
    expect(reply, "220", "SMTP");
    let codes = final_codes(reply);
    if codes.len() < 2 || codes[1] != "250" {
        refused("SMTP EHLO", reply);
    }
    let upper = reply.to_upper();
    if upper.contains("STARTTLS") {
        return;
    }
    if upper.contains("AUTH ") || upper.contains("AUTH=") {
        return #{
            title: "SMTP authentication without STARTTLS",
            severity: "MEDIUM",
            summary: "The SMTP server offers authentication but no STARTTLS, so credentials travel in cleartext.",
            evidence: clip(reply, 160)
        };
    }
    return #{
        title: "SMTP without STARTTLS",
        severity: "LOW",
        summary: "The SMTP server does not advertise STARTTLS, so mail it relays or receives travels in cleartext.",
        evidence: clip(reply, 160)
    };
}
