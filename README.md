# tor-fetcher

Like curl, but for fetching .onion URLs that require "haproxy-protection"/"BasedFlare"/Tartarus PoW completion before access is granted.

Uses Golang's argon2 and sha256 libraries instead of running the Javascript/WebAssembly bundle.

## Usage

```
tor-fetcher --target <url> [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | (required) | The URL to retrieve |
| `--proxy` | `socks5://127.0.0.1:9050` | SOCKS5 proxy address for Tor |
| `--ua` | Firefox 140 on Windows | User-Agent string |
| `--debug` | `false` | Enable debug logging to stderr |
| `-p` | `1` | Argon2 parallelism |
| `-l` | `32` | Argon2 key length |
| `--method` / `-X` | `GET` | HTTP request method, e.g. `POST` |
| `--data` / `-d` | (none) | `application/x-www-form-urlencoded` POST body, e.g. `"foo=bar&baz=qux"` |
| `--cookie` / `-b` | (none) | Read cookies for `--target`'s host from this JSON file before fetching |
| `--cookie-jar` / `-c` | (none) | Write cookies for `--target`'s host to this JSON file after fetching |
| `--trace` | `false` | Print the request/redirect/challenge chain to stderr |

### Submitting a form that needs a session (e.g. a XenForo search)

A form POST that requires a matching CSRF token generally also requires the
session cookie it was issued under — a token scraped from an unrelated page
load won't validate. Establish the session first, then reuse it:

```
# 1. GET a page to start a session and read its CSRF token from the HTML.
tor-fetcher --target https://forum.onion/ --cookie-jar session.json > page.html
token=$(grep -o '_xfToken" value="[^"]*"' page.html | cut -d'"' -f3)

# 2. POST the form using the SAME session.
tor-fetcher -X POST --cookie session.json \
  --data "keywords=example&c[users]=someuser&order=date&_xfToken=${token}" \
  --target https://forum.onion/search/search
```
