package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
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

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
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
var method = flag.String("method", "GET", "HTTP request method, e.g. HEAD")
var trace = flag.Bool("trace", false, "Print the request/redirect/challenge chain to stderr")
var postData = flag.String("data", "", "application/x-www-form-urlencoded POST body, e.g. \"foo=bar&baz=qux\"")
var cookieIn = flag.String("cookie", "", "Read cookies for --target's host from this JSON file before fetching (see --cookie-jar)")
var cookieOut = flag.String("cookie-jar", "", "Write cookies for --target's host to this JSON file after fetching")

func init() {
	// Curl-style alias for --method.
	flag.StringVar(method, "X", "GET", "alias for --method")
	// Curl-style alias for --data.
	flag.StringVar(postData, "d", "", "alias for --data")
	// Curl-style alias for --cookie.
	flag.StringVar(cookieIn, "b", "", "alias for --cookie")
	// Curl-style alias for --cookie-jar.
	flag.StringVar(cookieOut, "c", "", "alias for --cookie-jar")
}

// tracef prints a line to stderr describing a step in the fetch chain when
// --trace is enabled. Unlike --debug it is concise and aimed at following
// redirects and challenges.
func tracef(format string, args ...any) {
	if *trace {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func main() {
	flag.Parse()
	if *debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}
	targetURL, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("parsing --target: %v", err)
	}

	tc := NewTorClient()
	if *cookieIn != "" {
		if err := loadCookies(*cookieIn, tc.c.Jar, targetURL); err != nil {
			log.Fatalf("loading --cookie: %v", err)
		}
	}
	resp, err := tc.Fetch(*target, "", []byte(*postData))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if *cookieOut != "" {
		if err := saveCookies(*cookieOut, tc.c.Jar, resp.Request.URL); err != nil {
			log.Fatalf("saving --cookie-jar: %v", err)
		}
	}

	// Surface the status line and headers on stderr for non-200 responses
	// (and HEAD, which has no body) so failures and probes are debuggable.
	if resp.StatusCode != http.StatusOK || strings.EqualFold(*method, "HEAD") {
		fmt.Fprintf(os.Stderr, "HTTP %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
		resp.Header.Write(os.Stderr)
		fmt.Fprintln(os.Stderr)
	}

	body, err := decodeBody(resp)
	if err != nil {
		log.Fatal(err)
	}
	// Print the body even on errors so the actual content is visible.
	os.Stdout.Write(body)

	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}

// jsonCookie is the on-disk shape used by --cookie/--cookie-jar. It carries
// just enough of http.Cookie to round-trip a session between separate
// tor-fetcher invocations (e.g. fetch a page to establish a session and CSRF
// token, then POST a form using that same session).
type jsonCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// loadCookies reads cookies from path and installs them into jar for u's
// origin, so a subsequent Fetch(u, ...) reuses the session.
func loadCookies(path string, jar http.CookieJar, u *url.URL) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cookies []jsonCookie
	if err := json.Unmarshal(data, &cookies); err != nil {
		return err
	}
	httpCookies := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		httpCookies = append(httpCookies, &http.Cookie{Name: c.Name, Value: c.Value})
	}
	jar.SetCookies(u, httpCookies)
	return nil
}

// saveCookies writes jar's cookies for u's origin to path as JSON.
func saveCookies(path string, jar http.CookieJar, u *url.URL) error {
	var cookies []jsonCookie
	for _, c := range jar.Cookies(u) {
		cookies = append(cookies, jsonCookie{Name: c.Name, Value: c.Value})
	}
	data, err := json.MarshalIndent(cookies, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// decodeBody reads a response body, transparently decompressing the
// Content-Encodings we advertise in Accept-Encoding. Decoding is our job, not
// the transport's: Go only decompresses automatically when IT added the
// Accept-Encoding header, and setHeaders sets it explicitly to match Firefox.
// Every path that reads a body must go through here — reading a compressed
// challenge page raw yields binary that matches no challenge marker.
func decodeBody(resp *http.Response) ([]byte, error) {
	// HEAD responses carry the encoding header but no body to decode.
	if resp.Request != nil && resp.Request.Method == "HEAD" {
		return nil, nil
	}
	switch enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
		return io.ReadAll(resp.Body)
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		return io.ReadAll(gz)
	case "br":
		return io.ReadAll(brotli.NewReader(resp.Body))
	case "zstd":
		zr, err := zstd.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("zstd: %w", err)
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case "deflate":
		// "deflate" is zlib-wrapped in most servers but raw flate in some, and
		// the two are only distinguishable by trying.
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			defer zr.Close()
			return io.ReadAll(zr)
		}
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		return io.ReadAll(fr)
	default:
		// Fail loudly rather than hand back bytes that no caller can parse.
		return nil, fmt.Errorf("unsupported Content-Encoding %q", enc)
	}
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

// tartarusChallengePath is where Tartarus serves PoW parameters and accepts
// solutions. It is a dedicated endpoint, never a destination resource.
const tartarusChallengePath = "/.ttrs/challenge"

// checkTartarusCapability reports whether TartarusParams.Check can evaluate a
// challenge advertising the given algorithm/steps. Check implements exactly
// single-step SHA256 over salt+nonce, so anything else must be rejected
// explicitly: silently treating an unsupported algorithm or step count as
// sha256/steps=1 would submit a nonce that looks locally valid but is wrong
// -- a worse failure than refusing outright, since it burns a solve attempt
// (and a clearance-granting circuit) without any indication of why. Absent
// attributes mean the defaults, which are supported.
func checkTartarusCapability(algorithm, steps string) error {
	if algorithm != "" && algorithm != "sha256" {
		return fmt.Errorf("unsupported tartarus algorithm %q (only sha256 is implemented)", algorithm)
	}
	if steps != "" && steps != "1" {
		return fmt.Errorf("unsupported tartarus step count %q (only steps=1 is implemented)", steps)
	}
	return nil
}

// parseTartarusChallenge extracts the PoW salt and difficulty from a Tartarus
// challenge document. Two shapes are accepted: the HTML interstitial, which
// carries them as data-ttrs-* attributes, and the JSON object served by
// tartarusChallengePath. A non-nil error means either the document isn't a
// Tartarus challenge at all, or it is one but advertises PoW rules Check
// can't evaluate -- both must be treated the same way by the caller: don't
// submit a nonce.
func parseTartarusChallenge(body string) (TartarusParams, error) {
	if salt := extractAttr(body, "data-ttrs-challenge"); salt != "" {
		difficultyStr := extractAttr(body, "data-ttrs-difficulty")
		difficulty, err := strconv.Atoi(difficultyStr)
		if err != nil || difficulty <= 0 {
			return TartarusParams{}, fmt.Errorf("data-ttrs-challenge present but data-ttrs-difficulty is missing or invalid (%q)", difficultyStr)
		}
		if err := checkTartarusCapability(extractAttr(body, "data-ttrs-algorithm"), extractAttr(body, "data-ttrs-steps")); err != nil {
			return TartarusParams{}, err
		}
		return TartarusParams{salt: salt, difficulty: uint(difficulty)}, nil
	}

	var j struct {
		Salt       string `json:"salt"`
		Challenge  string `json:"challenge"`
		Difficulty any    `json:"difficulty"`
		Algorithm  string `json:"algorithm"`
		Steps      any    `json:"steps"`
	}
	if err := json.Unmarshal([]byte(body), &j); err != nil {
		return TartarusParams{}, fmt.Errorf("no data-ttrs-challenge attribute, and not JSON either: %w", err)
	}
	salt := j.Salt
	if salt == "" {
		salt = j.Challenge
	}
	var difficulty int
	switch d := j.Difficulty.(type) {
	case float64:
		difficulty = int(d)
	case string:
		difficulty, _ = strconv.Atoi(d)
	}
	if salt == "" || difficulty <= 0 {
		return TartarusParams{}, fmt.Errorf("JSON challenge missing salt/challenge or difficulty")
	}
	var steps string
	switch s := j.Steps.(type) {
	case float64:
		steps = strconv.Itoa(int(s))
	case string:
		steps = s
	}
	if err := checkTartarusCapability(j.Algorithm, steps); err != nil {
		return TartarusParams{}, err
	}
	return TartarusParams{salt: salt, difficulty: uint(difficulty)}, nil
}

// tartarusChallengeParams asks tartarusChallengePath for the PoW parameters
// directly. Interstitials that leave the salt/difficulty out of the HTML (the
// page's JS fetches them) are otherwise unsolvable. Safe in HEAD mode: the
// endpoint is never the destination resource, so it can't download the body a
// HEAD probe exists to avoid.
func (tc *TorClient) tartarusChallengeParams(requestURL *url.URL, referer string) (TartarusParams, error) {
	chURL := fmt.Sprintf("%s://%s%s", requestURL.Scheme, requestURL.Host, tartarusChallengePath)
	resp, err := tc.Get(chURL, referer)
	if err != nil {
		return TartarusParams{}, fmt.Errorf("fetching %s: %w", chURL, err)
	}
	body, err := decodeBody(resp)
	resp.Body.Close()
	tracef("GET %s -> %d %s (challenge params)", chURL, resp.StatusCode, http.StatusText(resp.StatusCode))
	if err != nil {
		return TartarusParams{}, fmt.Errorf("reading %s: %w", chURL, err)
	}
	p, err := parseTartarusChallenge(string(body))
	if err != nil {
		return TartarusParams{}, fmt.Errorf("no usable challenge parameters at %s (HTTP %d): %w; full body: %q",
			chURL, resp.StatusCode, err, body)
	}
	return p, nil
}

// tartarusChallengeURL reports the URL to GET for a Tartarus challenge's
// salt/difficulty when resp signals an API-style challenge via a 401 with a
// `Www-Authenticate: Tartarus ... challenge_url="..."` header — the shape
// used by XHR/form endpoints (e.g. a search POST), as opposed to the classic
// 203/403 page interstitial where the target itself IS the challenge page.
// Returns nil when resp isn't this kind of challenge.
func tartarusChallengeURL(resp *http.Response) *url.URL {
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}
	auth := resp.Header.Get("Www-Authenticate")
	if !strings.HasPrefix(auth, "Tartarus ") {
		return nil
	}
	loc := extractAttr(auth, "challenge_url")
	if loc == "" {
		return nil
	}
	resolved, err := resp.Request.URL.Parse(loc)
	if err != nil {
		return nil
	}
	return resolved
}

// torBrowserClientHello returns the TLS ClientHello Tor Browser 15.0.19 sends.
//
// utls's stock Firefox presets do NOT work here. The newest is
// HelloFirefox_120 (what HelloFirefox_Auto resolves to), and no Tor Browser was
// ever built on Firefox 120 -- TB 14 is Firefox 128 ESR, TB 15 is 140 ESR. Two
// concrete consequences: the 120 preset offers
// TLS_ECDHE_ECDSA_WITH_AES_{128,256}_CBC_SHA, which Tor Browser disables
// outright (security.ssl3.ecdhe_ecdsa_aes_{128,256}_sha in 001-base-profile.js),
// and it lacks the X25519MLKEM768 post-quantum key share that Firefox has sent
// since 132. Offering suites no Tor Browser offers is a positive tell, not just
// a gap.
//
// This spec was captured, not guessed: Firefox 140.13.0esr (the build Tor
// Browser 15.0.19 ships) was run against a local listener with Tor Browser's
// TLS prefs applied, and the raw ClientHello was decoded with utls's
// Fingerprinter. TestTorBrowserClientHello pins the properties that matter.
func torBrowserClientHello() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// No ECDHE_ECDSA CBC_SHA suites here: Tor Browser disables them.
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				utls.CurveID(256), // ffdhe2048
				utls.CurveID(257), // ffdhe3072
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.FakeDelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					utls.ECDSAWithSHA1,
				},
			},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
				{Group: utls.CurveP256},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					utls.PSSWithSHA256,
					utls.PSSWithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA256,
					utls.PKCS1WithSHA384,
					utls.PKCS1WithSHA512,
					utls.ECDSAWithSHA1,
					utls.PKCS1WithSHA1,
				},
			},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
				utls.CertCompressionBrotli,
				utls.CertCompressionZstd,
			}},
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
				},
				CandidatePayloadLens: []uint16{223},
			},
		},
	}
}

type TorClient struct {
	c http.Client
}

// The header sets below are transcribed from a capture of Firefox 140.13.0esr
// -- the exact build Tor Browser 15.0.19 ships -- running with Tor Browser's
// own prefs applied, requesting a local server. See TestTorBrowserHeaders for
// the recorded captures and the procedure.
//
// The goal is to be served the same bytes as any other anonymous Tor user, not
// merely to avoid being blocked, so anything NOT observed in that capture is
// deliberately not sent: an extra header is as much of a tell as a missing
// one. Notably absent is DNT, which Firefox would send but Tor Browser turns
// off (privacy.donottrackheader.enabled=false in 001-base-profile.js).
const (
	// htmlAccept is the document Accept. Firefox 140 sends no image types here
	// (older versions included image/webp).
	htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	// acceptLanguage is Firefox 140's value. Note 153 sends q=0.9 instead --
	// copying a newer Firefox here would make us stand out, not blend in.
	acceptLanguage  = "en-US,en;q=0.5"
	acceptEncoding  = "gzip, deflate, br, zstd"
	formContentType = "application/x-www-form-urlencoded"
)

// setCommonHeaders applies the headers Tor Browser sends on every request,
// whatever its kind.
func setCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", *ua)
	req.Header.Set("Accept-Language", acceptLanguage)
	// Tor Browser inherits Firefox's default for secure origins, and treats
	// .onion as a secure context (dom.securecontext.allowlist_onions). Firefox
	// added zstd here in 126.
	req.Header.Set("Accept-Encoding", acceptEncoding)
	// privacy.globalprivacycontrol.enabled is true in 001-base-profile.js.
	req.Header.Set("Sec-GPC", "1")
}

// isOnion reports whether u is an onion service address.
func isOnion(u *url.URL) bool {
	return strings.HasSuffix(strings.ToLower(u.Hostname()), ".onion")
}

// setReferer applies Tor Browser's network.http.referer.hideOnionSource: a page
// on a .onion never leaks its own URL as a Referer. Since essentially every
// request we make is referred from a .onion, this suppresses the header in
// practice -- sending one would mark us out immediately.
func setReferer(req *http.Request, referer string) {
	if referer == "" {
		return
	}
	u, err := url.Parse(referer)
	if err != nil || isOnion(u) {
		return
	}
	req.Header.Set("Referer", referer)
}

// setHeaders applies the headers Tor Browser sends for a top-level navigation
// (the equivalent of typing a URL), which is what a plain fetch of a page is.
func setHeaders(req *http.Request, referer string) {
	setCommonHeaders(req)
	req.Header.Set("Accept", htmlAccept)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")
	setReferer(req, referer)
}

// setFormPostHeaders applies the headers for a form submitted from a page on
// the same origin -- how BasedFlare's solution is returned. It is still a
// navigation, so it differs from setHeaders only in carrying an Origin and
// reporting same-origin rather than none.
func setFormPostHeaders(req *http.Request, page *url.URL, referer string) {
	setCommonHeaders(req)
	req.Header.Set("Accept", htmlAccept)
	req.Header.Set("Content-Type", formContentType)
	req.Header.Set("Origin", page.Scheme+"://"+page.Host)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")
	setReferer(req, referer)
}

// setXHRHeaders applies the headers a fetch() from page JavaScript sends --
// what Tartarus's challenge POST actually is. A browser sends Accept: */* here,
// not application/json, and carries an Origin.
func setXHRHeaders(req *http.Request, page *url.URL) {
	setCommonHeaders(req)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Content-Type", formContentType)
	req.Header.Set("Origin", page.Scheme+"://"+page.Host)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Priority", "u=4")
	setReferer(req, page.String())
}

// do issues a request with the given method (GET, HEAD, POST, ...). reqBody
// is nil for bodyless requests; when non-empty it is sent as an
// application/x-www-form-urlencoded body (e.g. for -X POST -d "...").
func (tc *TorClient) do(method, target, referer string, reqBody []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if len(reqBody) > 0 {
		bodyReader = strings.NewReader(string(reqBody))
	}
	req, err := http.NewRequest(method, target, bodyReader)
	if err != nil {
		return nil, err
	}
	if len(reqBody) > 0 {
		// A request with a form body is a form submission, not a typed URL.
		setFormPostHeaders(req, req.URL, referer)
	} else {
		setHeaders(req, referer)
	}
	return tc.c.Do(req)
}

func (tc *TorClient) Get(target, referer string) (*http.Response, error) {
	return tc.do("GET", target, referer, nil)
}

func (tc *TorClient) PostForm(target, referer string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	setFormPostHeaders(req, req.URL, referer)
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
		// TLS handshake with Tor Browser's fingerprint.
		// Skip verification: onion services authenticate via the .onion
		// address itself, so the server cert is cosmetic and often expired.
		cfg := &utls.Config{ServerName: host, InsecureSkipVerify: true}
		uConn := utls.UClient(rawConn, cfg, utls.HelloCustom)
		if err := uConn.ApplyPreset(torBrowserClientHello()); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("applying Tor Browser ClientHello: %w", err)
		}
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

func (tc *TorClient) Fetch(target, referer string, reqBody []byte) (*http.Response, error) {
	method := strings.ToUpper(*method)
	if method == "" {
		method = "GET"
	}
	currentURL := target
	currentReferer := referer

	// Challenges are always solved with GET (we need the HTML body and a
	// clearance cookie). finalize re-issues the destination request with the
	// caller's method (and body) once clearance is established. For plain
	// GET it is a no-op, so there is no extra round trip in the common case.
	finalize := func(resp *http.Response) (*http.Response, error) {
		if method == "GET" {
			return resp, nil
		}
		u := resp.Request.URL.String()
		ref := resp.Request.Header.Get("Referer")
		resp.Body.Close()
		tracef("%s %s (after clearance)", method, u)
		return tc.do(method, u, ref, reqBody)
	}

	for range 10 { // max redirect/challenge hops
		resp, err := tc.do(method, currentURL, currentReferer, reqBody)
		if err != nil {
			return nil, err
		}
		tracef("%s %s -> %d %s", method, currentURL, resp.StatusCode, http.StatusText(resp.StatusCode))

		// Follow redirects manually (we disabled auto-follow).
		if loc := resp.Header.Get("Location"); loc != "" &&
			(resp.StatusCode >= 300 && resp.StatusCode < 400) {
			resp.Body.Close()
			resolved, err := resp.Request.URL.Parse(loc)
			if err != nil {
				return nil, fmt.Errorf("bad redirect Location %q: %w", loc, err)
			}
			tracef("  -> redirect to %s", resolved)
			slog.Debug("following redirect", "from", currentURL, "to", resolved)
			currentReferer = currentURL
			currentURL = resolved.String()
			continue
		}

		// Not a challenge — return directly (with the caller's method).
		challengeURL := tartarusChallengeURL(resp)
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNonAuthoritativeInfo && challengeURL == nil {
			return resp, nil
		}

		// Body-safety for HEAD probes. Only a 203 Tartarus interstitial is safe
		// to resolve in HEAD mode: Tartarus consistently gates every unsolved
		// request, so the challenge-reading GET below returns the challenge
		// page, never the resource. A 403 is different — it is intermittent and
		// indistinguishable from a genuine Forbidden, and resolving it means
		// GETing the target to read a "challenge" body that may actually BE the
		// resource (downloading it). A HEAD probe exists precisely to avoid
		// fetching the body, so refuse a 403 outright rather than fall back to a
		// GET of the target. The caller can retry for a clean Tartarus-only pass.
		// (The 401 API-style challenge below is always safe: its GET target is
		// the dedicated /.ttrs/challenge endpoint, never the destination
		// resource, so there's nothing to leak.)
		if method == "HEAD" && resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return nil, fmt.Errorf("refusing to resolve a 403 challenge for a HEAD request: it would require a GET of the target that could download the body; retry for a Tartarus-only pass")
		}

		// The original target URL to retry once clearance is established.
		// Captured before chResp may point at a different challenge endpoint.
		requestURL := resp.Request.URL

		// Read the challenge body. Bodyless methods can't see it, and an
		// API-style 401 challenge carries the salt/difficulty on a separate
		// endpoint, not the response we already have — refetch with GET
		// whenever the challenge body isn't already what we're holding.
		fetchURL := currentURL
		if challengeURL != nil {
			fetchURL = challengeURL.String()
		}
		chResp := resp
		if method != "GET" || fetchURL != currentURL {
			resp.Body.Close()
			chResp, err = tc.do("GET", fetchURL, currentReferer, nil)
			if err != nil {
				return nil, err
			}
			tracef("GET %s -> %d %s (challenge body)", fetchURL, chResp.StatusCode, http.StatusText(chResp.StatusCode))
		}
		bodyBytes, err := decodeBody(chResp)
		chResp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading challenge body from %s: %w", fetchURL, err)
		}
		body := string(bodyBytes)

		// Identify the challenge by a POSITIVE match on each type. BasedFlare
		// must never be the fallback: solveBasedFlare parses no parameters out
		// of an unrecognized body, leaving difficulty 0, which Check() accepts
		// at nonce 0 — so an unknown challenge would silently POST a garbage
		// pow_response to the target instead of failing.
		p, parseErr := parseTartarusChallenge(body)
		switch {
		case parseErr == nil:
			tracef("  -> Tartarus challenge")
		case strings.Contains(body, "data-pow="):
			tracef("  -> BasedFlare challenge")
			bfResp, err := tc.solveBasedFlare(requestURL, body)
			if err != nil {
				return nil, err
			}
			return finalize(bfResp)
		default:
			var chErr error
			p, chErr = tc.tartarusChallengeParams(requestURL, currentReferer)
			if chErr != nil {
				return nil, fmt.Errorf("unrecognized %d challenge at %s: no BasedFlare parameters in the body; interstitial body unusable (%v); challenge endpoint also failed: %w; full interstitial body: %q",
					resp.StatusCode, fetchURL, parseErr, chErr, body)
			}
			tracef("  -> Tartarus challenge (params from %s)", tartarusChallengePath)
		}

		challengeResp, err := tc.solveTartarus(method, requestURL, p, reqBody)
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
			tracef("  -> redirect after challenge to %s", resolved)
			slog.Debug("following redirect after challenge", "from", requestURL, "to", resolved)
			currentReferer = requestURL.String()
			currentURL = resolved.String()
			continue
		}
		return finalize(challengeResp)
	}
	return nil, fmt.Errorf("too many redirects/challenges")
}

// tartarusMaxSolveAttempts bounds the retry-on-server-signal loop in
// solveTartarus: a rejected submission can carry an explicit action:"retry",
// and that's real, bounded, self-resolving signal rather than an unknown
// failure mode, so it's safe to retry automatically -- but bounded, so a
// challenge that's rejected for some other reason still fails loudly rather
// than looping.
const tartarusMaxSolveAttempts = 4

// tartarusMaxSameSaltRetries bounds how many of those retries continue
// brute-forcing the SAME salt for the next valid nonce, which is cheap (no
// extra network round trip): server-side rejection was confirmed live to be
// scoped to the specific (salt, nonce) pair, not the salt as a whole, so
// resuming the same search past a rejected nonce is normally enough. If it
// still isn't after a couple of tries, something else may be going on, so
// the remaining attempts escalate to fetching an entirely fresh challenge
// instead of exhausting the whole budget on a salt that might never redeem.
const tartarusMaxSameSaltRetries = 2

func (tc *TorClient) solveTartarus(method string, requestURL *url.URL, p TartarusParams, reqBody []byte) (*http.Response, error) {
	referer := requestURL.String()
	var lastErr error
	nextNonce := 0 // resume point for the current salt's brute-force search
	sameSaltRetries := 0
	for attempt := 1; attempt <= tartarusMaxSolveAttempts; attempt++ {
		// Brute-force SHA256 PoW, resuming past any nonce already rejected
		// for this salt rather than restarting from 0 (which would just
		// find that same rejected nonce again).
		var nonce int
		for n := nextNonce; ; n++ {
			if p.Check(n) {
				nonce = n
				break
			}
		}
		nextNonce = nonce + 1

		// POST the solution to /.ttrs/challenge as an XHR.
		challengeURL := fmt.Sprintf("%s://%s%s", requestURL.Scheme, requestURL.Host, tartarusChallengePath)
		values := url.Values{}
		values.Set("salt", p.salt)
		values.Set("nonce", strconv.Itoa(nonce))
		slog.Debug("tartarus challenge solved", "salt", p.salt, "difficulty", p.difficulty, "nonce", nonce, "attempt", attempt)
		req, err := http.NewRequest("POST", challengeURL, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, fmt.Errorf("building tartarus POST: %w", err)
		}
		// In a browser this POST is a fetch() issued by the interstitial's
		// script, so it carries the XHR header set, not a page navigation's.
		setXHRHeaders(req, requestURL)
		postResp, err := tc.c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("posting tartarus solution: %w", err)
		}
		postBody, _ := io.ReadAll(postResp.Body)
		postResp.Body.Close()
		slog.Debug("tartarus POST response", "status", postResp.StatusCode, "body", string(postBody))
		slog.Debug("tartarus POST cookies", "set-cookie", postResp.Header["Set-Cookie"])

		if postResp.StatusCode == http.StatusOK {
			if tc.c.Jar != nil {
				slog.Debug("tartarus jar cookies", "url", requestURL, "cookies", tc.c.Jar.Cookies(requestURL))
			}
			// Re-fetch the original target with the CALLER'S method and body
			// now that the ttrs_clearance cookie is set (the jar preserves
			// it). Using the caller's method rather than a hardcoded GET
			// means a HEAD probe never downloads the destination body --
			// essential when the caller must learn a resource's status
			// without fetching the resource itself. For GET this is
			// unchanged.
			return tc.do(method, requestURL.String(), requestURL.String(), reqBody)
		}

		lastErr = fmt.Errorf("tartarus challenge POST to %s returned %d (submitted salt=%s difficulty=%d nonce=%d, attempt %d/%d): response body: %q",
			challengeURL, postResp.StatusCode, p.salt, p.difficulty, nonce, attempt, tartarusMaxSolveAttempts, postBody)

		var reject struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(postBody, &reject); err != nil || reject.Action != "retry" || attempt == tartarusMaxSolveAttempts {
			break
		}

		if sameSaltRetries < tartarusMaxSameSaltRetries {
			sameSaltRetries++
			continue
		}
		newP, err := tc.tartarusChallengeParams(requestURL, referer)
		if err != nil {
			lastErr = fmt.Errorf("%w (fetching a fresh challenge to retry also failed: %v)", lastErr, err)
			break
		}
		// The "fresh" challenge can come back with the SAME salt (observed
		// live: the challenge endpoint's salt is itself coarsely time-
		// bucketed, and a whole retry sequence can complete inside one
		// bucket). Resetting the nonce search to 0 in that case would just
		// resubmit the exact nonce that already lost -- only restart the
		// search when the salt actually changed; otherwise keep advancing
		// through the same search we were already running.
		if newP.salt != p.salt {
			nextNonce = 0
			sameSaltRetries = 0
		}
		p = newP
	}
	return nil, lastErr
}

func (tc *TorClient) solveBasedFlare(requestURL *url.URL, body string) (*http.Response, error) {
	var p ArgonParams
	var pow string
	for _, l := range strings.Split(body, "\n") {
		// Match on the attribute rather than the line's exact indentation, so a
		// template whitespace change doesn't silently zero out the parameters.
		if !strings.Contains(l, "data-pow=") {
			continue
		}
		start := strings.Index(l, "<body ")
		if start == -1 {
			continue
		}
		attrs := l[start+len("<body "):]
		if end := strings.Index(attrs, ">"); end != -1 {
			attrs = attrs[:end]
		}

		for _, part := range strings.Fields(attrs) {
			key, value, found := strings.Cut(part, "=")
			if !found {
				continue
			}
			// Trim the quotes on either side of the value.
			value = strings.Trim(value, `"`)
			switch key {
			case "data-pow":
				pow = value
				params := strings.Split(pow, "#")
				if len(params) != 2 {
					return nil, fmt.Errorf("malformed basedflare data-pow %q, want salt#prefix", pow)
				}
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
				// Tolerate attributes we don't consume (class, onload, ...);
				// the completeness check below is what guards correctness.
				slog.Debug("ignoring basedflare body attribute", "key", key, "value", value)
			}
		}
		p.parallelism = uint8(*parallelism)
		p.keyLength = uint32(*length)
		break
	}

	// Refuse to "solve" a challenge we couldn't read. With zero parameters
	// difficulty is 0, which Check() accepts at nonce 0, so submitting anyway
	// posts a garbage pow_response that the server rejects far from the cause.
	if pow == "" || p.iterations == 0 || p.memory == 0 {
		return nil, fmt.Errorf("incomplete BasedFlare challenge parameters (pow=%q time=%d kb=%d diff=%d); body starts: %.200q",
			pow, p.iterations, p.memory, p.difficulty, body)
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
