// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
//
// POP3 AUTH NTLM observation (phase 8, docs/pulse-plugin-phases.ru.md): offer
// the NTLM mechanism and, when the server continues with "+", send a minimal
// type1 that names no workstation, to see whether a type2 challenge comes
// back. No USER/PASS, no CAPA (shapo_cleartext_services owns the capability
// list), no type3 and no credentials are ever sent.
//
// The dialogue needs both records on one socket. Pulse's sandbox opens a fresh
// connection per probe call today, so the type1 lands in a new POP3 session:
// that server greets again and never answers the blob with a type2. That is
// the documented blocked outcome: it is raised, not reported as a clean port
// the check did not really make, and the two steps are never glued into one
// packet to work around the engine.
//
// The type1 travels as hex: the text call cannot write a byte above 0x7f (its
// 0x82 flag byte would come out as two UTF-8 bytes), and the hex reply is
// byte-preserving, so the type2 checks are real - signature, message type,
// and the security-buffer lengths against the frame.

fn name() {
    "shapo_pop3_ntlm"
}

fn description() {
    "Observe a POP3 server that answers AUTH NTLM with an NTLM type2 challenge."
}

fn ports() {
    []
}

// The answer to our command is the first line that is not the greeting: the
// plugin's own connection is greeted with "+OK ..." again before the server
// answers AUTH NTLM.
fn pop3_answer(reply) {
    for raw in reply.split("\n") {
        let line = raw;
        line.trim();
        if line == "" {
            continue;
        }
        if line.to_upper().starts_with("+OK") {
            continue;
        }
        return line;
    }
    ""
}

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

fn hex_digit(c) {
    let at = "0123456789abcdef".index_of(c.to_lower());
    if at < 0 {
        throw "garbled hex digit in the POP3 reply";
    }
    at
}

fn hex_u16(hex, byte_pos) {
    let start = byte_pos * 2;
    let stop = start + 4;
    let value = 0;
    for i in start..stop {
        value = value * 16 + hex_digit(hex.sub_string(i, 1));
    }
    value
}

fn hex_u32(hex, byte_pos) {
    let start = byte_pos * 2;
    let stop = start + 8;
    let value = 0;
    for i in start..stop {
        value = value * 16 + hex_digit(hex.sub_string(i, 1));
    }
    value
}

fn run() {
    if !(service == "pop3") {
        return;
    }

    // Step 1: offer the NTLM mechanism. A server that supports it answers with
    // a lone "+" and waits for the type1 blob, so the call ends at the read
    // deadline rather than at EOF; a refusal is a "-ERR" line.
    let reply = probe_send(port, "AUTH NTLM\r\n", 1500);
    if reply.starts_with("pulse-error:") {
        throw "POP3 AUTH NTLM probe failed: " + reply;
    }
    if reply.len() == 0 {
        throw "empty POP3 reply to AUTH NTLM";
    }
    let answer = pop3_answer(reply);
    if answer == "" {
        throw "no answer to AUTH NTLM in the POP3 reply";
    }
    if answer.starts_with("-ERR") {
        return;
    }
    if !(answer.starts_with("+")) {
        return;
    }

    // Step 2: the continuation. Same minimal type1 as the IMAP check.
    let challenge = probe_send_hex(port, "4e544c4d53535000010000000782080000000000000000000000000000000000", 1500);
    if challenge.starts_with("pulse-error:") {
        throw "POP3 NTLM type1 probe failed: " + challenge;
    }
    if challenge.len() == 0 {
        throw "empty POP3 reply to the NTLM type1";
    }

    let at = challenge.index_of("4e544c4d53535000");
    if at < 0 {
        // No type2. A fresh POP3 session greets the new connection instead of
        // answering the blob, which is the blocked signal; a refusal or any
        // other answer on the kept socket means NTLM was not continued.
        if first_line(challenge).to_upper().starts_with("+OK") {
            throw "blocked: the NTLM type1 ran on a new POP3 connection (the server greeted again instead of answering); the sandbox cannot keep the AUTH NTLM socket between probe calls";
        }
        return;
    }

    let frame = challenge.sub_string(at);
    let frame_bytes = frame.len() / 2;
    if frame.len() % 2 != 0 || frame_bytes < 48 {
        throw "truncated NTLM type2 in the POP3 reply: " + frame_bytes + " bytes, the fixed header alone is 48";
    }
    if frame.sub_string(16, 8) != "02000000" {
        throw "the POP3 reply carries the NTLMSSP signature but the message is not a type2";
    }
    // The security buffers must lie inside the frame they were parsed from.
    let name_len = hex_u16(frame, 12);
    let name_off = hex_u32(frame, 16);
    if name_len > 0 && name_off + name_len > frame_bytes {
        throw "NTLM type2 target name runs past the POP3 frame";
    }
    let info_len = hex_u16(frame, 40);
    let info_off = hex_u32(frame, 44);
    if info_len > 0 && info_off + info_len > frame_bytes {
        throw "NTLM type2 target info runs past the POP3 frame";
    }

    return #{
        title: "POP3 server answers AUTH NTLM with an NTLM type2 challenge",
        severity: "LOW",
        summary: "The server continued the AUTH NTLM handshake and returned an NTLM type2 challenge to a minimal, nameless type1. Only the mechanism was observed: no credentials, no NTLM type3 and no USER/PASS login were sent.",
        evidence: "The POP3 server replied to AUTH NTLM with a continuation and returned a parsed NTLM type2 challenge."
    };
}
