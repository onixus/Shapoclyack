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

fn clip(text, limit) {
    let one_line = text;
    one_line.replace("\r", "");
    one_line.replace("\n", " | ");
    if one_line.len() > limit { one_line.sub_string(0, limit) } else { one_line }
}

// A failed probe is raised, not swallowed: an empty result would read as
// "checked, clean" to a verification re-scan (docs/pulse-plugins.md).
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
