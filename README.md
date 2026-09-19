# certwatch

A TLS certificate expiry watcher. "The cert expired and nobody noticed"
is a recurring, embarrassing outage class; today's fixes are SaaS
monitors. This is a single binary you can run from cron or CI. A natural
companion to this workspace's `localcert` — that one issues *local dev*
certs, this one watches *production* domains' real certs.

## Usage

```bash
certwatch example.com                          # defaults to :443
certwatch example.com:8443 api.example.com
certwatch --file domains.txt --warn-days 14     # one host[:port] per line, # comments allowed
```

Exit code `1` if anything is expired or within `--warn-days` (default
30) of expiring — cron/CI-friendly by design.

## Reads certs it wouldn't otherwise trust — on purpose

Normal TLS trust validation would make the handshake itself *fail* on
exactly the certificates this tool exists to find (expired, self-signed,
wrong host) — so it uses a certificate verifier that accepts anything,
purely to complete the handshake and read the real leaf certificate back.
This is never used to decide whether anything is trustworthy, only to
report its actual expiry regardless of trust status — documented
explicitly in `tls.rs`, not a quiet security shortcut.

## Status: built, verified with unit tests, then genuinely caught a real bug via live internet testing

- **9 unit tests** (`cargo test --lib`): day-counting math (whole days
  remaining, already-expired correctly negative), status classification
  at every boundary (`Ok`/`Warning`/`Expired`, including exactly on the
  threshold and exactly at zero days), the `host`/`host:port` parser, and
  — using a **real self-signed certificate generated with `rcgen`**, not a
  hand-written DER fixture — confirming the X.509 parser correctly
  extracts subject/issuer/`not_after` from actual certificate bytes, plus
  garbage bytes producing a clean error rather than a panic.
- **Live-verified against real internet TLS endpoints, and this is where
  a real bug was actually caught, not just exercised**: the first version
  drove the handshake via `Stream::write_all(b"")`, which passed every
  unit test (none of them touch a real socket) but turned out to be a
  silent no-op against a real server — a zero-length write never reaches
  the underlying socket, so the handshake never actually completed, and
  every live check failed with "no peer certificates presented." Caught
  immediately by testing against `github.com` for real, fixed by driving
  the handshake with `conn.complete_io()` directly, then reverified:
  - `github.com` → real, correct certificate, `CN=github.com`, healthy.
  - `expired.badssl.com` (badssl.com hosts intentionally-broken certs
    specifically for testing TLS clients) → correctly flagged
    **`EXPIRED`** with the real (large negative) day count.
  - `self-signed.badssl.com` → correctly **connects and reads** the cert
    despite it being untrusted by any normal browser — proving the
    "accept-any-cert" verifier actually does what it claims, not just
    that it compiles.
  - A port with nothing listening → a clean connection error, not a hang
    or a panic.
  - Multiple targets in one run, with `--warn-days` correctly flipping a
    healthy-but-soon-expiring cert (`github.com`, 37 days out) from `OK`
    to `WARNING` when the threshold was raised past 37.

**Not done / deliberately deferred**: SAN (Subject Alternative Name)
listing in the output (only the subject DN is shown; SANs are what
browsers actually match against for multi-domain certs, a real
completeness gap); OCSP/CRL revocation checking (out of scope — this
watches expiry, not revocation, a genuinely different problem); and
concurrent checking (targets are checked one at a time, sequentially —
fine for a handful of domains from cron, would want parallelizing for a
few hundred).
