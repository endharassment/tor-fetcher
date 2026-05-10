package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/argon2"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

var parallelism = flag.Int("p", 1, "Parallelism")
var length = flag.Int("l", 32, "Length")
var target = flag.String("target", "", "The URL to retrieve (required)")
var ua = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0", "Tor user agent by default")
var socksAddr = flag.String("proxy", "socks5://127.0.0.1:9050", "SOCKS5 proxy address for Tor")
var debug = flag.Bool("debug", false, "Enable debug logging")

func main() {
	flag.Parse()
	if *debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}
	tc := NewTorClient()
	resp, err := tc.Fetch(*target, "")
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Non-200 status code: %d\n", resp.StatusCode)
	}

	defer resp.Body.Close()

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		defer reader.Close()
	default:
		reader = resp.Body
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))
}

type ArgonParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
	difficulty  int
	prefix      string
	salt        string
}

func (p ArgonParams) Check(n int) bool {
	if p.difficulty == 0 {
		return true
	}
	password := fmt.Sprintf("%s%d", p.prefix, n)
	hash := argon2.IDKey([]byte(password), []byte(p.salt), p.iterations, p.memory, p.parallelism, p.keyLength)
	for i, v := range hash[:(p.difficulty+1)/2] {
		if 2*i == p.difficulty {
			return true
		}
		if v != 0 {
			if 2*i+1 == p.difficulty && v>>4 == 0 {
				return true
			}
			break
		}
	}
	return false
}

type TartarusParams struct {
	salt       string
	difficulty uint
}

func (p TartarusParams) Check(n int) bool {
	input := p.salt + strconv.Itoa(n)
	hash := sha256.Sum256([]byte(input))
	val := binary.BigEndian.Uint32(hash[:4])
	return val < (1 << (32 - p.difficulty))
}

// extractAttr extracts the value of an HTML attribute from a string.
// e.g. extractAttr(`<html data-foo="bar">`, "data-foo") returns "bar".
func extractAttr(s, attr string) string {
	key := attr + `="`
	idx := strings.Index(s, key)
	if idx == -1 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(s[start:], `"`)
	if end == -1 {
		return ""
	}
	return s[start : start+end]
}

type TorClient struct {
	c http.Client
}

func setHeaders(req *http.Request, referer string) {
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	req.Header.Set("User-Agent", *ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func (tc *TorClient) Get(target, referer string) (*http.Response, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(req, referer)
	return tc.c.Do(req)
}

func (tc *TorClient) PostForm(target, referer string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	setHeaders(req, referer)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return tc.c.Do(req)
}

// utlsTransport is an http.RoundTripper that dials TLS with utls
// (for browser-like fingerprints) and dispatches to HTTP/2 or HTTP/1.1
// based on the ALPN-negotiated protocol.
type utlsTransport struct {
	dialTLS func(ctx context.Context, network, addr string) (net.Conn, error)

	mu      sync.Mutex
	h2Conns map[string]*http2.ClientConn
}

func (t *utlsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	hostPort := net.JoinHostPort(addr, port)

	// Try reusing a cached HTTP/2 connection.
	t.mu.Lock()
	cc := t.h2Conns[hostPort]
	t.mu.Unlock()
	if cc != nil {
		slog.Debug("transport: reusing h2 conn", "method", req.Method, "url", req.URL)
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		slog.Debug("transport: cached h2 conn failed, dialing new", "err", err)
		t.mu.Lock()
		delete(t.h2Conns, hostPort)
		t.mu.Unlock()
	} else {
		slog.Debug("transport: no cached conn, dialing new", "method", req.Method, "url", req.URL)
	}

	conn, err := t.dialTLS(req.Context(), "tcp", hostPort)
	if err != nil {
		return nil, err
	}

	// Check ALPN negotiated protocol.
	alpn := ""
	if uconn, ok := conn.(*utls.UConn); ok {
		alpn = uconn.ConnectionState().NegotiatedProtocol
	}

	if alpn == "h2" {
		cc, err := (&http2.Transport{}).NewClientConn(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		t.mu.Lock()
		if t.h2Conns == nil {
			t.h2Conns = make(map[string]*http2.ClientConn)
		}
		t.h2Conns[hostPort] = cc
		t.mu.Unlock()
		return cc.RoundTrip(req)
	}

	// HTTP/1.1 fallback.
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return resp, nil
}

func NewTorClient() *TorClient {
	proxyURL, err := url.Parse(*socksAddr)
	if err != nil {
		log.Fatalf("Failed to parse proxy URL %q: %v\n", *socksAddr, err)
	}
	socksDialer, err := proxy.FromURL(proxyURL, proxy.Direct)
	if err != nil {
		log.Fatalf("Failed to create SOCKS dialer: %v\n", err)
	}

	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		// TCP dial through the SOCKS5 proxy.
		rawConn, err := socksDialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// TLS handshake with Firefox fingerprint.
		// Skip verification: onion services authenticate via the .onion
		// address itself, so the server cert is cosmetic and often expired.
		cfg := &utls.Config{ServerName: host, InsecureSkipVerify: true}
		uConn := utls.UClient(rawConn, cfg, utls.HelloFirefox_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return uConn, nil
	}

	jar, _ := cookiejar.New(nil)
	httpClient := http.Client{
		Transport: &utlsTransport{dialTLS: dialTLS},
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects automatically; Fetch() handles them.
			return http.ErrUseLastResponse
		},
	}
	return &TorClient{c: httpClient}
}

func (tc *TorClient) Fetch(target, referer string) (*http.Response, error) {
	currentURL := target
	currentReferer := referer

	for range 10 { // max redirect/challenge hops
		resp, err := tc.Get(currentURL, currentReferer)
		if err != nil {
			return nil, err
		}

		// Follow redirects manually (we disabled auto-follow).
		if loc := resp.Header.Get("Location"); loc != "" &&
			(resp.StatusCode >= 300 && resp.StatusCode < 400) {
			resp.Body.Close()
			resolved, err := resp.Request.URL.Parse(loc)
			if err != nil {
				return nil, fmt.Errorf("bad redirect Location %q: %w", loc, err)
			}
			slog.Debug("following redirect", "from", currentURL, "to", resolved)
			currentReferer = currentURL
			currentURL = resolved.String()
			continue
		}

		// Not a challenge — return directly.
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNonAuthoritativeInfo {
			return resp, nil
		}

		// Read the challenge body.
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		body := string(bodyBytes)
		requestURL := resp.Request.URL

		if strings.Contains(body, "data-ttrs-challenge") {
			challengeResp, err := tc.solveTartarus(requestURL, body)
			if err != nil {
				return nil, err
			}
			// solveTartarus returns the re-GET response; loop to
			// handle further redirects or challenges on the new domain.
			if loc := challengeResp.Header.Get("Location"); loc != "" &&
				(challengeResp.StatusCode >= 300 && challengeResp.StatusCode < 400) {
				challengeResp.Body.Close()
				resolved, err := requestURL.Parse(loc)
				if err != nil {
					return nil, fmt.Errorf("bad redirect Location %q: %w", loc, err)
				}
				slog.Debug("following redirect after challenge", "from", requestURL, "to", resolved)
				currentReferer = requestURL.String()
				currentURL = resolved.String()
				continue
			}
			return challengeResp, nil
		}
		return tc.solveBasedFlare(requestURL, body)
	}
	return nil, fmt.Errorf("too many redirects/challenges")
}

func (tc *TorClient) solveTartarus(requestURL *url.URL, body string) (*http.Response, error) {
	salt := extractAttr(body, "data-ttrs-challenge")
	diffStr := extractAttr(body, "data-ttrs-difficulty")
	difficulty, err := strconv.Atoi(diffStr)
	if err != nil {
		return nil, fmt.Errorf("parsing tartarus difficulty: %w", err)
	}

	p := TartarusParams{salt: salt, difficulty: uint(difficulty)}

	// Brute-force SHA256 PoW from nonce=0.
	var nonce int
	for n := 0; ; n++ {
		if p.Check(n) {
			nonce = n
			break
		}
	}

	// POST the solution to /.ttrs/challenge as an XHR.
	challengeURL := fmt.Sprintf("%s://%s/.ttrs/challenge", requestURL.Scheme, requestURL.Host)
	values := url.Values{}
	values.Set("salt", salt)
	values.Set("nonce", strconv.Itoa(nonce))
	slog.Debug("tartarus challenge solved", "salt", salt, "difficulty", difficulty, "nonce", nonce)
	req, err := http.NewRequest("POST", challengeURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building tartarus POST: %w", err)
	}
	req.Header.Set("Referer", requestURL.String())
	req.Header.Set("User-Agent", *ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResp, err := tc.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting tartarus solution: %w", err)
	}
	postBody, _ := io.ReadAll(postResp.Body)
	postResp.Body.Close()
	slog.Debug("tartarus POST response", "status", postResp.StatusCode, "body", string(postBody))
	slog.Debug("tartarus POST cookies", "set-cookie", postResp.Header["Set-Cookie"])
	if postResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tartarus challenge POST returned %d", postResp.StatusCode)
	}

	if tc.c.Jar != nil {
		slog.Debug("tartarus jar cookies", "url", requestURL, "cookies", tc.c.Jar.Cookies(requestURL))
	}

	// Re-GET the original target (cookie jar preserves ttrs_clearance).
	return tc.Get(requestURL.String(), requestURL.String())
}

func (tc *TorClient) solveBasedFlare(requestURL *url.URL, body string) (*http.Response, error) {
	var p ArgonParams
	var pow string
	for _, l := range strings.Split(body, "\n") {
		if !strings.HasPrefix(l, "\t<body data") {
			continue
		}
		parts := strings.Split(l[len("\t<body "):len(l)-1], " ")

		for _, part := range parts {
			split := strings.SplitN(part, "=", 2)
			key := split[0]
			// Trim the quotes on either side of the value.
			value := split[1][1 : len(split[1])-1]
			switch key {
			case "data-pow":
				pow = value
				params := strings.Split(pow, "#")
				p.salt = params[0]
				p.prefix = params[1]
			case "data-time":
				iters, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("parsing basedflare time: %w", err)
				}
				p.iterations = uint32(iters)
			case "data-diff":
				bits, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("parsing basedflare diff: %w", err)
				}
				p.difficulty = bits / 8
			case "data-kb":
				mem, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("parsing basedflare kb: %w", err)
				}
				p.memory = uint32(mem)
			default:
				return nil, fmt.Errorf("unexpected basedflare key: %s", key)
			}
		}
		p.parallelism = uint8(*parallelism)
		p.keyLength = uint32(*length)
		break
	}

	// Run the POW, single-threaded in case another circuit is running.
	var result int
	for n := 0; ; n++ {
		if p.Check(n) {
			result = n
			break
		}
	}

	// Post the result back to the checker.
	values := url.Values{}
	values.Set("pow_response", fmt.Sprintf("%s#%d", pow, result))
	values.Set("submit", "submit")
	return tc.PostForm(requestURL.String(), requestURL.String(), values)
}
