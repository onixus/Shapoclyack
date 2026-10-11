// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
//
// HTTP TRACE enabled (replaces Nmap's http-trace, #547), plain HTTP only.
//
// The sandbox speaks TCP and has no TLS, so an https listener is out of reach
// (the gate lets only service "http", or a reply that opens with "HTTP/", in).
// The request carries a marker header; the finding needs a 200 whose body
// echoes that header back, which is what TRACE is for. A server that answers
// 200 to everything (a stub, a catch-all) does not echo and is not reported.
// One call: "Connection: close" makes the server end the reply at EOF.
//
// What counts as an error and what as clean: a reply that is not HTTP at all is
// raised (the service is not what the gate took it for, and "clean" would be a
// lie). A reply with no bytes -- the server hung up on the unknown method, as
// some proxies and WAFs do -- is read as TRACE refused: no finding, no error.
// So a server that stalls or resets for an unrelated reason also reads clean,
// and a hang-up cannot confirm that a fix worked; the finding is LOW and the
// next scan asks again. A service that echoes every request with
// a 200 (a debugging echo server) is reported although it has no TRACE method:
// the plugin cannot tell the two apart from one reply.

fn name() {
    "shapo_http_trace"
}

fn description() {
    "Report plain-HTTP servers that answer TRACE by echoing the request."
}

fn ports() {
    []
}

fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}

fn run() {
    let greeting = banner.to_lower();
    if !(service == "http" || greeting.starts_with("http/")) {
        return;
    }

    let marker = "shapo-trace-547";
    let reply = probe_send(port, "TRACE / HTTP/1.1\r\nHost: shapoclyack.invalid\r\nX-Shapo-Trace: " + marker + "\r\nConnection: close\r\n\r\n", 1500);
    // No bytes: see the note at the top. Not an error, and not evidence of a fix.
    if reply.len() == 0 {
        return;
    }
    let lines = reply.split("\n");
    let status = "";
    if lines.len() > 0 {
        status = lines[0];
        status.trim();
    }
    if !status.starts_with("HTTP/") {
        throw "no HTTP status line in the reply to TRACE: " + head(reply, 60);
    }
    // "HTTP/1.1 200 OK": the code follows the first space.
    let parts = status.split(" ");
    if parts.len() < 2 || parts[1] != "200" {
        return;
    }
    // Only the body counts: the header lines of the reply are the server's own.
    let sep = reply.index_of("\r\n\r\n");
    let body = "";
    if sep >= 0 {
        body = reply.sub_string(sep + 4);
    } else {
        let alt = reply.index_of("\n\n");
        if alt >= 0 {
            body = reply.sub_string(alt + 2);
        }
    }
    if body.contains("X-Shapo-Trace: " + marker) {
        return #{
            title: "HTTP TRACE method enabled",
            severity: "LOW",
            summary: "The server answers TRACE with 200 and echoes the request, headers included. That reflects what a browser sends (cookies, authorisation headers) back to a script that can issue TRACE (cross-site tracing). Disable it: Apache TraceEnable off, nginx and most others refuse it by default. Plain HTTP only: HTTPS listeners are not checked.",
            evidence: head(status, 80) + " (request echoed)"
        };
    }
}
