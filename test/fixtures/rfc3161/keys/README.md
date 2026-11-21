# Test-only keys

Test-only keys for the RFC 3161 tests; never used for real timestamps. They were made by
`../generate.sh`, protect nothing, and anything signed by them or chaining to
`../certs/ca.pem` must never be trusted.
