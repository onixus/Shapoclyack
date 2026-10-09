"""Honest stand-ins for services with no usable Linux image: IIS and RDP.

These are NOT the real products. They speak just enough of the protocol to
produce the banner/headers (IIS) or the X.224 negotiation answer (RDP) that
detection logic looks at, so the corpus records what each tool does with that
wire format, not what IIS or Windows would do. Marked as stubs in meta.json.
"""

import socketserver
import sys

# TPKT + X.224 Connection Confirm carrying RDP_NEG_RSP (selected: CredSSP).
RDP_CC = bytes.fromhex("03000013" "0ed000001234" "00" "02000800" "02000000")

IIS_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Server: Microsoft-IIS/10.0\r\n"
    b"X-Powered-By: ASP.NET\r\n"
    b"Content-Length: 22\r\n"
    b"Connection: close\r\n\r\n"
    b"<html>IIS stub</html>\n"
)


class IIS(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            self.request.recv(4096)
        except OSError:
            pass
        self.request.sendall(IIS_RESPONSE)


class RDP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            self.request.recv(4096)
            self.request.sendall(RDP_CC)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    mode, port = sys.argv[1], int(sys.argv[2])
    Server(("0.0.0.0", port), {"iis": IIS, "rdp": RDP}[mode]).serve_forever()
