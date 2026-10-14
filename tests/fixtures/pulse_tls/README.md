# Local wire evidence

`raw_tls13.json` records the initial direct raw enumerator against a local
OpenSSL TLS1.3 server. `raw_postgres_tls13.json` records a local protocol shim
that accepts the PostgreSQL SSLRequest and then switches to OpenSSL TLS1.3.
It exercised the candidate source snapshot `c54ae18` with this CLI binary hash:

SHA256: `fa6cd5dc89e30bb2897676abde249d93b24f2136eee096979127d9ac090b8451`

The PostgreSQL fixture is an actual emitted engine row, with three observed
suites, server preference, and the normal x25519 share/253-bit curve size.
It is not native PostgreSQL database acceptance, authentication, a signed
release, or installed-device acceptance. No SQL or credentials were sent.
The temporary private key was destroyed; only certificate facts and negotiated
metadata appear in the fixture. The server rejected other versions and the
remaining suite offers were inconclusive, so `complete` remains false.
