# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build              # Build ./tor-fetcher binary
go test ./...         # Run all tests
go test -v -run TestTartarusCheck  # Run a single test
gofmt -w main.go      # Format before committing
```

CI runs on CircleCI with `cimg/go:1.26` (large resource class): `go install ./...` then `go test ./...`.

## What This Tool Does

tor-fetcher is a curl-like CLI for fetching .onion URLs protected by proof-of-work challenges (BasedFlare/haproxy-protection and Tartarus). It solves PoW challenges natively in Go (Argon2 for BasedFlare, SHA256 for Tartarus) instead of running the sites' JavaScript/WebAssembly bundles.

## Architecture

All code lives in a single `main.go` (~810 lines) with tests in `main_test.go`. This is intentional — keep it in one file.

**Module path:** `github.com/endharassment/tor-fetcher`.

### Key Types

- **`TorClient`** — Wraps `http.Client` with cookie jar, manual redirect handling, and custom transport. Entry point is `Fetch()` which loops through challenge-solve-retry cycles (max 10 hops).
- **`utlsTransport`** — Custom `http.RoundTripper` using uTLS Firefox fingerprints for browser-like TLS. Supports HTTP/2 via ALPN with per-host connection caching. Dials through SOCKS5 proxy.
- **`ArgonParams`** — BasedFlare PoW: Argon2id key derivation, nonce must produce hash with N leading zero nibbles.
- **`TartarusParams`** — Tartarus PoW: SHA256-based, nonce must produce hash below `1 << (32 - difficulty)`.

### Challenge Flow

`Fetch()` detects challenges via HTTP 203/403 status codes (plus the API-style 401 + `Www-Authenticate: Tartarus`). Each challenge type is matched **positively**: Tartarus via `parseTartarusChallenge` (`data-ttrs-*` attributes, or the JSON served by `/.ttrs/challenge`), BasedFlare via `data-pow=`. Neither is the fallback — an unrecognized body errors out, because a solver handed no parameters would otherwise submit a bogus zero-difficulty solution. When an interstitial carries no inline parameters, `tartarusChallengeParams` GETs `/.ttrs/challenge` for them. Solvers brute-force nonces, POST the solution, and the resulting clearance cookie allows the re-GET to succeed.

Challenge bodies must be read through `decodeBody`, never `io.ReadAll`: `setHeaders` sets `Accept-Encoding` explicitly (for the Firefox fingerprint), which turns OFF Go's automatic decompression, so a gzipped interstitial otherwise arrives as binary that matches no challenge marker.

### Matching Tor Browser

The tool impersonates Tor Browser, and the bar is **being served the same bytes as any other anonymous Tor user**, not merely not being blocked. So a header we send that Tor Browser doesn't is as much of a tell as one we're missing, and every value is captured rather than guessed.

Two things are pinned to Tor Browser, both in `main.go` and asserted by `TestTorBrowserHeaders` / `TestTorBrowserClientHello`:

- **Request headers** — `setHeaders` (top-level navigation), `setFormPostHeaders` (form submission), `setXHRHeaders` (the Tartarus challenge POST, which in a browser is a `fetch()`). Notable: the document `Accept` carries no image types, `Accept-Language` is `q=0.5` (Firefox 153 says `q=0.9` — do not copy a newer Firefox), `Sec-GPC: 1` is sent, `DNT` is **not** (Tor Browser sets `privacy.donottrackheader.enabled=false`), and `Referer` is suppressed whenever the referring page is a `.onion` (`network.http.referer.hideOnionSource`).
- **TLS ClientHello** — `torBrowserClientHello()`. utls's stock presets are unusable here: the newest is `HelloFirefox_120`, no Tor Browser was built on Firefox 120, and it offers `TLS_ECDHE_ECDSA_WITH_AES_{128,256}_CBC_SHA` which Tor Browser disables outright — advertising suites no Tor Browser advertises is a positive tell.

**Re-capturing when Tor Browser updates** (the version is in `about:support`; TB 15.0.19 ships Firefox 140.13.0esr):

1. Download the matching stock Firefox ESR from `ftp.mozilla.org`. Tor Browser's own binary won't work for this — TorConnect gates navigation until Tor bootstraps — but TB is that ESR plus prefs, so stock ESR with TB's prefs in a profile `user.js` is equivalent.
2. Copy the header-relevant prefs out of `000-tor-browser.js` / `001-base-profile.js` (`privacy.resistFingerprinting`, `privacy.globalprivacycontrol.enabled`, `browser.privatebrowsing.autostart`, the `security.ssl3.*` cipher disables, `security.ssl.disable_session_identifiers`) into the profile.
3. Run it headless against a local listener that dumps raw request bytes. Use `127.0.0.1` or `localhost`, which count as trustworthy origins, so you get the `Sec-Fetch-*` set and the secure `Accept-Encoding` without any cert setup.
4. For the ClientHello, read the first TLS record off the socket and decode it with `utls.Fingerprinter`. Use a hostname, not an IP — an IP literal suppresses SNI and hides its position in the extension order.

### Key Dependencies

| Dependency | Purpose |
|-----------|---------|
| `refraction-networking/utls` | Firefox TLS fingerprinting |
| `golang.org/x/crypto` | Argon2id hashing |
| `golang.org/x/net` | HTTP/2 + SOCKS5 proxy dialing |

### CLI Flags

`--target` (required URL), `--proxy` (default `socks5://127.0.0.1:9050`), `--ua` (User-Agent), `--method`/`-X` (HTTP method, default `GET`, e.g. `HEAD`), `--trace` (print the request/redirect/challenge chain to stderr), `--debug` (slog debug to stderr), `-p` (Argon2 parallelism), `-l` (Argon2 key length).

On non-200 responses (and HEAD), the status line and headers are written to stderr and the body is still printed to stdout; the process exits non-zero on non-200. Challenges are always solved with GET (the solver needs the HTML body and clearance cookie); the chosen method is applied to the destination request once clearance is established.

## Testing Notes

Tests use table-driven style. `TestSolveTartarusFlow` is an integration test that spins up an HTTPS test server simulating the challenge-response flow. Tests run fast (~10ms) and don't require a running Tor daemon.
