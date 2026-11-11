// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
//
// SMTP AUTH NTLM observation (phase 8, docs/pulse-plugin-phases.ru.md): EHLO,
// then AUTH NTLM on the 250 answer, then the same minimal NTLM type1 the IMAP
// and POP3 checks send, on the 334 continuation. A parsed type2 challenge
// confirms the mechanism. No MAIL FROM, RCPT TO, VRFY, EXPN or NTLM type3 is
// ever sent: this is mechanism observation, not a relay or a login test.
//
// The dialogue needs all records on one socket. Pulse's sandbox opens a fresh
// connection per probe call today, so any later step lands in a new SMTP
// session: that server greets with "220" again instead of answering, which is
// the documented blocked outcome - it is raised with the reason, never read as
// a clean port the check did not really make, and the steps are never glued
// into one packet to work around the engine.
//
// The type1 travels base64-encoded in one text line, and the 334 payload is
// base64 too, so the text call carries the whole exchange. The challenge is
// decoded only far enough to prove a well-formed type2: signature, message
// type 2, and the security-buffer lengths inside the frame. Host, domain and
// target names from the challenge are never copied into the evidence.

fn name() {
    "shapo_smtp_ntlm"
}

fn description() {
    "Observe whether an SMTP server answers AUTH NTLM with a parsed NTLM type2 challenge."
}

fn ports() {
    []
}

fn head(text, limit) {
    let one_line = text;
    one_line.replace("\r", " ");
    one_line.replace("\n", " | ");
    if one_line.len() > limit { one_line.sub_string(0, limit) } else { one_line }
}

// The first non-empty line of a reply.
fn first_line(reply) {
    for raw in reply.split("\n") {
        let line = raw;
        line.trim();
        if line != "" {
            return line;
        }
    }
    ""
}

// Decode one base64 line into bytes. An empty array means "not base64": a 334
// payload that does not decode is simply not an NTLM message, which is clean.
fn b64_decode(text) {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out = [];
    let acc = 0;
    let bits = 0;
    let i = 0;
    while i < text.len() {
        let ch = text.sub_string(i, 1);
        i += 1;
        if ch == "=" {
            continue;
        }
        let v = alphabet.index_of(ch);
        if v < 0 || v > 63 {
            return [];
        }
        acc = acc * 64 + v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = acc / (1 << bits);
            out.push(byte);
            acc = acc - byte * (1 << bits);
        }
    }
    out
}

// "" when the frame is a well-formed NTLM type2 challenge; "clean" when it is
// not an NTLM type2 at all; a throw when the signature and type say type2 but
// the frame is truncated (a failed probe is raised, not read as clean).
fn type2_verdict(frame) {
    let sig = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00];
    if frame.len() < 8 {
        return "clean";
    }
    for i in 0..8 {
        if frame[i] != sig[i] {
            return "clean";
        }
    }
    if frame.len() < 12 {
        throw "truncated NTLM type2 challenge: " + frame.len() + " bytes, the message type is cut";
    }
    if !(frame[8] == 2 && frame[9] == 0 && frame[10] == 0 && frame[11] == 0) {
        return "clean";
    }
    if frame.len() < 48 {
        throw "truncated NTLM type2 challenge: " + frame.len() + " bytes, the fixed header is 48";
    }
    // Target name security buffer: length u16le @12, offset u32le @16.
    let name_len = frame[12] + frame[13] * 256;
    let name_off = frame[16] + frame[17] * 256 + frame[18] * 65536 + frame[19] * 16777216;
    if name_len > 0 && name_off + name_len > frame.len() {
        throw "truncated NTLM type2 challenge: the target name runs beyond the frame";
    }
    // Target info security buffer: length u16le @40, offset u32le @44.
    let info_len = frame[40] + frame[41] * 256;
    let info_off = frame[44] + frame[45] * 256 + frame[46] * 65536 + frame[47] * 16777216;
    if info_len > 0 && info_off + info_len > frame.len() {
        throw "truncated NTLM type2 challenge: the target info runs beyond the frame";
    }
    ""
}

// The base64 payload after a "334" line; "" when the line carries no payload.
fn challenge_after(line) {
    if line.len() <= 3 {
        return "";
    }
    let rest = line.sub_string(3, line.len() - 3);
    rest.trim();
    rest
}

fn run() {
    if !(service == "smtp") {
        return;
    }

    // Step 1: EHLO. The plugin's own connection is greeted with "220" again
    // before the server answers, so the greeting lines are skipped; the EHLO
    // block must carry a 250 code and advertise AUTH, or the endpoint is clean.
    let reply = probe_send(port, "EHLO shapoclyack.invalid\r\n", 1500);
    if reply.starts_with("pulse-error:") {
        throw "SMTP EHLO probe failed: " + reply;
    }
    if reply.len() == 0 {
        throw "empty SMTP reply to EHLO";
    }
    let lines = [];
    for raw in reply.split("\n") {
        let line = raw;
        line.trim();
        if line != "" {
            lines.push(line);
        }
    }
    let i = 0;
    while i < lines.len() && lines[i].starts_with("220") {
        i += 1;
    }
    if lines.len() <= i || !lines[i].starts_with("250") {
        throw "EHLO answered without a 250 code: " + head(reply, 80);
    }
    let block = "";
    let j = i;
    while j < lines.len() && lines[j].starts_with("250") {
        block += lines[j];
        block += "\n";
        j += 1;
    }
    if !block.to_upper().contains("AUTH") {
        return;
    }

    // Step 2: offer the NTLM mechanism. A greeting here means the call ran on
    // a new connection, which is the documented blocked outcome.
    let offered = probe_send(port, "AUTH NTLM\r\n", 1500);
    if offered.starts_with("pulse-error:") {
        throw "SMTP AUTH NTLM probe failed: " + offered;
    }
    if offered.len() == 0 {
        throw "empty SMTP reply to AUTH NTLM";
    }
    let answer = first_line(offered);
    if answer.starts_with("220") {
        throw "blocked: AUTH NTLM ran on a new SMTP connection (the server greeted again instead of answering); the sandbox cannot keep the EHLO socket between probe calls";
    }
    if answer.starts_with("5") {
        return;
    }
    if !answer.starts_with("334") {
        throw "no 334 challenge after AUTH NTLM: " + head(answer, 80);
    }

    // Step 3: the same minimal type1 as the IMAP and POP3 checks, base64 in
    // one text line. The empty 334 above challenged it; this answer decides.
    let type1 = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=";
    let challenge = probe_send(port, type1 + "\r\n", 1500);
    if challenge.starts_with("pulse-error:") {
        throw "SMTP NTLM type1 probe failed: " + challenge;
    }
    if challenge.len() == 0 {
        throw "empty SMTP reply to the NTLM type1";
    }
    let line = first_line(challenge);
    if line.starts_with("220") {
        throw "blocked: the NTLM type1 ran on a new SMTP connection (the server greeted again instead of answering); the sandbox cannot keep the AUTH NTLM socket between probe calls";
    }
    if line.starts_with("5") {
        return;
    }
    if !line.starts_with("334") {
        throw "unexpected reply to the NTLM type1: " + head(line, 80);
    }
    let candidate = challenge_after(line);
    if candidate == "" {
        return;
    }
    if type2_verdict(b64_decode(candidate)) != "" {
        return;
    }
    return #{
        title: "SMTP NTLM authentication mechanism observed",
        severity: "LOW",
        summary: "The server advertises AUTH NTLM and answered the audit's NTLM type1 with a type2 challenge. Observing the mechanism proves neither an open relay nor accepted credentials; no MAIL FROM, RCPT TO, VRFY, EXPN or NTLM type3 was sent.",
        evidence: "EHLO advertised AUTH, AUTH NTLM got a 334 challenge and the type1 was answered with a parsed NTLM type2 challenge"
    };
}
