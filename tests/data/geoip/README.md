# GeoIP test fixtures

`GeoIP2-City-Test.mmdb` is MaxMind’s public **GeoIP2 City test database** from
[maxmind/MaxMind-DB](https://github.com/maxmind/MaxMind-DB/tree/main/test-data)
(not a full GeoLite2 production DB). It is redistributed only for unit tests of
the `.mmdb` reader path.

Production scans should use a licensed GeoLite2-City download via
`scripts/fetch-geoip-db.sh`.
