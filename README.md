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
| `--trace` | `false` | Print the request/redirect/challenge chain to stderr |
