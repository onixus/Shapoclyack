// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 onixus
// Confirms: the wsman endpoint of a Windows HTTP-services listener answers an
// anonymous empty SOAP-content request with an HTTP-layer authentication
// challenge that names the Microsoft HTTPAPI/WSMan stack. Not checked: NTLM
// or Negotiate credentials (no type 3), any SOAP command, WS-Man Identify.
fn name() { "shapo_winrm_http" }
fn description() { "Detect a WinRM wsman endpoint answering with an HTTP authentication challenge." }
fn ports() { [] }
fn head(text, limit) {
    if text.len() > limit { text.sub_string(0, limit) } else { text }
}
fn run() {
    let unnamed = service == "" || service == "unknown";
    if !(service == "winrm" || (unnamed && port == 5985)) { return; }
    let reply = probe_send(port, "POST /wsman HTTP/1.1\r\nHost: shapoclyack.invalid\r\nContent-Type: application/soap+xml\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 1500);
    if reply.len() == 0 { throw "empty WinRM probe reply"; }
    let lines = reply.split("\n");
    let status = "";
    if lines.len() > 0 {
        status = lines[0];
        status.trim();
    }
    if !status.starts_with("HTTP/") { throw "WinRM probe reply is not HTTP: " + head(reply, 60); }
    let parts = status.split(" ");
    if parts.len() < 2 || parts[1].len() != 3 { throw "unparseable HTTP status line: " + head(status, 60); }
    if parts[1] != "401" { return; }
    let sep4 = reply.index_of("\r\n\r\n");
    let sep2 = reply.index_of("\n\n");
    if sep4 < 0 && sep2 < 0 { throw "no end of HTTP headers in the WinRM reply"; }
    let end = if sep4 >= 0 { sep4 } else { sep2 };
    let text = reply.sub_string(0, end).to_lower();
    if !(text.contains("www-authenticate:") && (text.contains("microsoft-httpapi") || text.contains("wsman"))) { return; }
    return #{
        title: "WinRM endpoint reachable with an HTTP-layer authentication challenge",
        severity: "LOW",
        summary: "The wsman endpoint answered 401 with a Windows-authentication challenge. No credentials were attempted and no SOAP command was sent.",
        evidence: "Anonymous POST /wsman returned 401 with WWW-Authenticate and a Microsoft HTTPAPI/WSMan marker."
    };
}
