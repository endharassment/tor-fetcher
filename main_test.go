package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utls "github.com/refraction-networking/utls"
)

func TestTartarusCheck(t *testing.T) {
	tests := []struct {
		name       string
		salt       string
		difficulty uint
		nonce      int
		want       bool
	}{
		{"difficulty 1, nonce 0 fails", "testsalt", 1, 0, false},
		{"difficulty 1, nonce 1 passes", "testsalt", 1, 1, true},
		{"difficulty 8, nonce 0 fails", "testsalt", 8, 0, false},
		{"difficulty 8, nonce 13 passes", "testsalt", 8, 13, true},
		{"real urlscan vector, fails nonce 0", "a92a106fa4e8c2398ebcabecefebf28c_69853ed8", 16, 0, false},
		{"real urlscan vector, passes known nonce", "a92a106fa4e8c2398ebcabecefebf28c_69853ed8", 16, 3026359506902472, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := TartarusParams{salt: tt.salt, difficulty: tt.difficulty}
			if got := p.Check(tt.nonce); got != tt.want {
				t.Errorf("TartarusParams{%q, %d}.Check(%d) = %v, want %v",
					tt.salt, tt.difficulty, tt.nonce, got, tt.want)
			}
		})
	}
}

func TestExtractAttr(t *testing.T) {
	tests := []struct {
		name string
		html string
		attr string
		want string
	}{
		{"finds attribute", `<html data-ttrs-challenge="abc123" data-ttrs-difficulty="16">`, "data-ttrs-challenge", "abc123"},
		{"finds second attribute", `<html data-ttrs-challenge="abc123" data-ttrs-difficulty="16">`, "data-ttrs-difficulty", "16"},
		{"missing attribute", `<html data-foo="bar">`, "data-ttrs-challenge", ""},
		{"empty value", `<html data-ttrs-challenge="">`, "data-ttrs-challenge", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractAttr(tt.html, tt.attr); got != tt.want {
				t.Errorf("extractAttr(%q, %q) = %q, want %q",
					tt.html, tt.attr, got, tt.want)
			}
		})
	}
}

func TestParseTartarusChallenge(t *testing.T) {
	// A live interstitial captured 2026-08-11, which carries the
	// algorithm/step attributes the older capture didn't.
	const liveHTML = `<html id="ttrs" class="no-js" data-ttrs-challenge="148f1bab6087189a9c5bbedb2604563d_6a7a78c0_17"
    data-ttrs-difficulty="17" data-ttrs-steps="1"
    data-ttrs-algorithm="sha256"
    data-ttrs-worker-v="ee91eb68">`

	tests := []struct {
		name           string
		body           string
		wantOK         bool
		wantSalt       string
		wantDifficulty uint
	}{
		{"live interstitial", liveHTML, true, "148f1bab6087189a9c5bbedb2604563d_6a7a78c0_17", 17},
		{"minimal html", `<html data-ttrs-challenge="abc" data-ttrs-difficulty="16">`, true, "abc", 16},
		{"json salt", `{"salt":"abc","difficulty":16}`, true, "abc", 16},
		{"json challenge alias", `{"challenge":"abc","difficulty":16}`, true, "abc", 16},
		{"json string difficulty", `{"salt":"abc","difficulty":"16"}`, true, "abc", 16},
		{"basedflare page", `<body data-pow="salt#prefix" data-time="1" data-kb="64" data-diff="8">`, false, "", 0},
		{"unrelated html", `<html><body>hello</body></html>`, false, "", 0},
		{"missing difficulty", `<html data-ttrs-challenge="abc">`, false, "", 0},
		// Unsupported PoW rules must read as unparsed rather than yield a nonce
		// computed the wrong way, which the server would reject.
		{"unsupported algorithm", `<html data-ttrs-challenge="abc" data-ttrs-difficulty="16" data-ttrs-algorithm="blake3">`, false, "", 0},
		{"multi-step challenge", `<html data-ttrs-challenge="abc" data-ttrs-difficulty="16" data-ttrs-steps="3">`, false, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := parseTartarusChallenge(tt.body)
			if ok != tt.wantOK {
				t.Fatalf("parseTartarusChallenge() ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if p.salt != tt.wantSalt || p.difficulty != tt.wantDifficulty {
				t.Errorf("parseTartarusChallenge() = {salt:%q difficulty:%d}, want {salt:%q difficulty:%d}",
					p.salt, p.difficulty, tt.wantSalt, tt.wantDifficulty)
			}
		})
	}
}

// TestTorBrowserHeaders pins our request headers to what Tor Browser actually
// sends. The expectations below are transcribed from captures of Firefox
// 140.13.0esr -- the build Tor Browser 15.0.19 ships -- run headless against a
// local listener with Tor Browser's own prefs applied (resistFingerprinting,
// globalprivacycontrol, private browsing, referer policies), reading the raw
// request bytes off the socket.
//
// The point is not just to avoid being blocked: it's to be served the same
// bytes as any other anonymous Tor user. So this asserts the header set
// EXACTLY, in both directions -- a header we send that Tor Browser doesn't is
// as much of a tell as one we're missing. DNT is the worked example: Firefox
// sends it, but Tor Browser sets privacy.donottrackheader.enabled=false, so we
// must not.
func TestTorBrowserHeaders(t *testing.T) {
	pageURL, err := url.Parse("https://example.onion/thread/1")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	tests := []struct {
		name string
		// build applies the header set under test to a request.
		build func(*http.Request)
		want  map[string]string
	}{
		{
			// Captured: GET / from a fresh window.
			name:  "top-level navigation",
			build: func(r *http.Request) { setHeaders(r, "") },
			want: map[string]string{
				"User-Agent":                *ua,
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language":           "en-US,en;q=0.5",
				"Accept-Encoding":           "gzip, deflate, br, zstd",
				"Sec-Gpc":                   "1",
				"Upgrade-Insecure-Requests": "1",
				"Sec-Fetch-Dest":            "document",
				"Sec-Fetch-Mode":            "navigate",
				"Sec-Fetch-Site":            "none",
				"Sec-Fetch-User":            "?1",
				"Priority":                  "u=0, i",
			},
		},
		{
			// Captured: fetch("/.ttrs/challenge", {method:"POST"}) from page JS.
			// A browser sends Accept: */* here, not application/json, and
			// carries an Origin. Referer is suppressed because the page is
			// a .onion (network.http.referer.hideOnionSource).
			name:  "challenge POST is an XHR",
			build: func(r *http.Request) { setXHRHeaders(r, pageURL) },
			want: map[string]string{
				"User-Agent":      *ua,
				"Accept":          "*/*",
				"Accept-Language": "en-US,en;q=0.5",
				"Accept-Encoding": "gzip, deflate, br, zstd",
				"Sec-Gpc":         "1",
				"Content-Type":    "application/x-www-form-urlencoded",
				"Origin":          "https://example.onion",
				"Sec-Fetch-Dest":  "empty",
				"Sec-Fetch-Mode":  "cors",
				"Sec-Fetch-Site":  "same-origin",
				"Priority":        "u=4",
			},
		},
		{
			// A form submitted from the page: still a navigation, but
			// same-origin and carrying an Origin.
			name:  "form submission",
			build: func(r *http.Request) { setFormPostHeaders(r, pageURL, pageURL.String()) },
			want: map[string]string{
				"User-Agent":                *ua,
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language":           "en-US,en;q=0.5",
				"Accept-Encoding":           "gzip, deflate, br, zstd",
				"Sec-Gpc":                   "1",
				"Content-Type":              "application/x-www-form-urlencoded",
				"Origin":                    "https://example.onion",
				"Upgrade-Insecure-Requests": "1",
				"Sec-Fetch-Dest":            "document",
				"Sec-Fetch-Mode":            "navigate",
				"Sec-Fetch-Site":            "same-origin",
				"Sec-Fetch-User":            "?1",
				"Priority":                  "u=0, i",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", pageURL.String(), nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			tt.build(req)

			for name, want := range tt.want {
				if got := req.Header.Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			// Nothing beyond the captured set: an extra header is a tell too.
			for name := range req.Header {
				if _, ok := tt.want[name]; !ok {
					t.Errorf("sending %s: %q, which Tor Browser does not send here",
						name, req.Header.Get(name))
				}
			}
		})
	}
}

func TestRefererHiddenForOnionSource(t *testing.T) {
	// network.http.referer.hideOnionSource: a page on a .onion never leaks its
	// URL as a Referer. Every hop we make is referred from a .onion, so sending
	// one would single us out immediately.
	tests := []struct {
		name    string
		referer string
		want    string
	}{
		{"onion source suppressed", "https://example.onion/page", ""},
		{"onion source with port suppressed", "https://example.onion:8443/page", ""},
		{"uppercase onion suppressed", "https://EXAMPLE.ONION/page", ""},
		{"clearnet source sent", "https://example.com/page", "https://example.com/page"},
		{"empty referer stays empty", "", ""},
		{"unparseable referer suppressed", "://nonsense", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://example.onion/", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			setReferer(req, tt.referer)
			if got := req.Header.Get("Referer"); got != tt.want {
				t.Errorf("Referer = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTorBrowserClientHello(t *testing.T) {
	spec := torBrowserClientHello()

	// The two suites Tor Browser disables in 001-base-profile.js
	// (security.ssl3.ecdhe_ecdsa_aes_{128,256}_sha). utls's HelloFirefox_120
	// offers both, so using the stock preset would advertise cipher suites no
	// Tor Browser ever advertises -- a positive tell, not just a gap.
	disabled := map[uint16]string{
		0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	}
	for _, c := range spec.CipherSuites {
		if name, bad := disabled[c]; bad {
			t.Errorf("offering %s (0x%04x), which Tor Browser disables", name, c)
		}
	}

	// Firefox has offered the post-quantum hybrid key share since 132, so a
	// hello without it does not match the version our User-Agent claims.
	var haveCurve, haveKeyShare bool
	var alpn []string
	for _, e := range spec.Extensions {
		switch v := e.(type) {
		case *utls.SupportedCurvesExtension:
			if len(v.Curves) > 0 && v.Curves[0] == utls.X25519MLKEM768 {
				haveCurve = true
			}
		case *utls.KeyShareExtension:
			for _, ks := range v.KeyShares {
				if ks.Group == utls.X25519MLKEM768 {
					haveKeyShare = true
				}
			}
		case *utls.ALPNExtension:
			alpn = v.AlpnProtocols
		}
	}
	if !haveCurve {
		t.Error("X25519MLKEM768 is not the first supported curve")
	}
	if !haveKeyShare {
		t.Error("no X25519MLKEM768 key share offered")
	}
	if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", alpn)
	}
	// SNI leads the extension list in the capture; ordering is fingerprinted.
	if len(spec.Extensions) == 0 {
		t.Fatal("no extensions")
	}
	if _, ok := spec.Extensions[0].(*utls.SNIExtension); !ok {
		t.Errorf("first extension is %T, want *utls.SNIExtension", spec.Extensions[0])
	}

	// The spec must be usable: ApplyPreset rejects malformed ones.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	uConn := utls.UClient(c1, &utls.Config{ServerName: "example.onion", InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uConn.ApplyPreset(torBrowserClientHello()); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
}

// testEncoders maps a Content-Encoding to something that produces it.
var testEncoders = map[string]func([]byte) []byte{
	"gzip":    gzipBytes,
	"deflate": zlibBytes,
	"br":      brotliBytes,
	"zstd":    zstdBytes,
}

func TestAdvertisedEncodingsAreDecodable(t *testing.T) {
	// Two properties at once. First, Accept-Encoding must match what Tor
	// Browser sends: it inherits Firefox's network.http.accept-encoding.secure
	// (neither 000-tor-browser.js nor 001-base-profile.js overrides it) and
	// treats .onion as a secure context, and Firefox has sent zstd there since
	// 126. Sending a pre-126 value alongside a Firefox 140 User-Agent is
	// exactly the sort of mismatch that makes a client stand out.
	//
	// Second, and more practically: every encoding we advertise must be one
	// decodeBody can actually decode. Advertising br without decoding it is
	// what left a live challenge page unreadable, so assert the two lists
	// agree rather than trusting them to be edited together.
	const want = "gzip, deflate, br, zstd"

	req, err := http.NewRequest("GET", "https://example.onion/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	setHeaders(req, "")
	got := req.Header.Get("Accept-Encoding")
	if got != want {
		t.Errorf("Accept-Encoding = %q, want %q (Tor Browser's value)", got, want)
	}

	const body = "<html>hello</html>"
	for _, enc := range strings.Split(got, ", ") {
		t.Run(enc, func(t *testing.T) {
			encode, ok := testEncoders[enc]
			if !ok {
				t.Fatalf("we advertise %q but no encoder exists to test it", enc)
			}
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", enc)
				w.Write(encode([]byte(body)))
			}))
			defer ts.Close()

			resp, err := ts.Client().Get(ts.URL + "/")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer resp.Body.Close()
			decoded, err := decodeBody(resp)
			if err != nil {
				t.Fatalf("decodeBody for advertised encoding %q: %v", enc, err)
			}
			if string(decoded) != body {
				t.Errorf("decodeBody = %q, want %q", decoded, body)
			}
		})
	}
}

func TestDecodeBody(t *testing.T) {
	// setHeaders sets Accept-Encoding itself, which switches OFF Go's automatic
	// decompression, so every body we read may be compressed.
	tests := []struct {
		name     string
		encoding string
		encode   func([]byte) []byte
		wantErr  bool
	}{
		{"identity", "", func(b []byte) []byte { return b }, false},
		{"gzip", "gzip", gzipBytes, false},
		{"brotli", "br", brotliBytes, false},
		{"zstd", "zstd", zstdBytes, false},
		{"zlib-wrapped deflate", "deflate", zlibBytes, false},
		{"raw deflate", "deflate", flateBytes, false},
		{"unsupported", "dcb", func(b []byte) []byte { return b }, true},
	}
	const want = "<html>hello</html>"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.encoding != "" {
					w.Header().Set("Content-Encoding", tt.encoding)
				}
				w.Write(tt.encode([]byte(want)))
			}))
			defer ts.Close()

			resp, err := ts.Client().Get(ts.URL + "/")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer resp.Body.Close()
			got, err := decodeBody(resp)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("decodeBody() = %q, want an error for Content-Encoding %q", got, tt.encoding)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeBody: %v", err)
			}
			if string(got) != want {
				t.Errorf("decodeBody() = %q, want %q", got, want)
			}
		})
	}
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func brotliBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func zstdBytes(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func zlibBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func flateBytes(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func TestFetchGzippedTartarusChallenge(t *testing.T) {
	// Regression: the live site began serving the 203 interstitial gzipped.
	// setHeaders advertises gzip explicitly, which disables Go's automatic
	// decompression, so reading the challenge body raw yields binary that
	// matches no Tartarus marker — and the fetcher misclassified it as
	// BasedFlare and POSTed a bogus pow_response to the target.
	const (
		wantSalt = "a92a106fa4e8c2398ebcabecefebf28c_69853ed8"
		wantDiff = "16"
	)
	challengeHTML := fmt.Sprintf(
		`<html id="ttrs" data-ttrs-challenge="%s" data-ttrs-difficulty="%s" data-ttrs-steps="1" data-ttrs-algorithm="sha256">`,
		wantSalt, wantDiff)

	var gotSalt string
	var sawBasedFlarePost bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.ttrs/challenge" && r.Method == "POST":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			gotSalt = form.Get("salt")
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test", Path: "/"})
			fmt.Fprint(w, `{"success":true}`)
		case r.URL.Path == "/":
			if r.Method == "POST" {
				// A BasedFlare-style solution POST to the target: the exact
				// wrong turn this test guards against.
				sawBasedFlarePost = true
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if _, err := r.Cookie("ttrs_clearance"); err != nil {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusNonAuthoritativeInfo)
				w.Write(gzipBytes([]byte(challengeHTML)))
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>real page</html>")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	defer setMethod("GET")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if sawBasedFlarePost {
		t.Error("a BasedFlare pow_response was POSTed to the target: the gzipped Tartarus challenge was misclassified")
	}
	if gotSalt != wantSalt {
		t.Errorf("Tartarus POST salt = %q, want %q", gotSalt, wantSalt)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, err := decodeBody(resp)
	if err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	if string(body) != "<html>real page</html>" {
		t.Errorf("body = %q, want the real page", body)
	}
}

func TestFetchTartarusParamsFromChallengeEndpoint(t *testing.T) {
	// An interstitial that leaves the salt/difficulty out of the HTML (its JS
	// fetches them) must still be solvable: fall back to the challenge endpoint
	// rather than misreading the page as a BasedFlare challenge.
	const wantSalt = "a92a106fa4e8c2398ebcabecefebf28c_69853ed8"

	var challengeGETs int
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.ttrs/challenge" && r.Method == "GET":
			challengeGETs++
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"salt":%q,"difficulty":16}`, wantSalt)
		case r.URL.Path == "/.ttrs/challenge" && r.Method == "POST":
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test", Path: "/"})
			fmt.Fprint(w, `{"success":true}`)
		case r.URL.Path == "/":
			if _, err := r.Cookie("ttrs_clearance"); err != nil {
				w.WriteHeader(http.StatusNonAuthoritativeInfo)
				fmt.Fprint(w, `<html id="ttrs"><script src="/.ttrs/worker.js"></script></html>`)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>real page</html>")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	defer setMethod("GET")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if challengeGETs == 0 {
		t.Error("challenge endpoint was never GET'd for the missing parameters")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestFetchUnrecognizedChallengeFailsLoudly(t *testing.T) {
	// With no recognizable parameters, solveBasedFlare used to leave difficulty
	// at 0 — which Check() satisfies at nonce 0 — and POST a garbage
	// pow_response to the target. Fetch must error instead.
	var sawPost bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			sawPost = true
		}
		if r.URL.Path == "/.ttrs/challenge" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><body>some challenge we have never seen</body></html>")
	}))
	defer ts.Close()
	defer setMethod("GET")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error on an unrecognized challenge, got nil")
	}
	if sawPost {
		t.Error("a solution was POSTed for a challenge that was never parsed")
	}
}

func TestFetchBasedFlareChallenge(t *testing.T) {
	// BasedFlare is now matched positively rather than used as the fallback;
	// make sure a real one still solves. Tiny Argon2 parameters keep it fast.
	var gotPOW string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			gotPOW = form.Get("pow_response")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>real page</html>")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		// data-diff is in bits; 8 bits == 1 leading zero nibble.
		fmt.Fprint(w, "<html>\n\t<body data-pow=\"salt#prefix\" data-time=\"1\" data-kb=\"64\" data-diff=\"8\" class=\"unknown-attr\">\n</html>")
	}))
	defer ts.Close()
	defer setMethod("GET")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	prefix := "salt#prefix#"
	if !strings.HasPrefix(gotPOW, prefix) {
		t.Fatalf("pow_response = %q, want prefix %q", gotPOW, prefix)
	}
	nonce, err := strconv.Atoi(strings.TrimPrefix(gotPOW, prefix))
	if err != nil {
		t.Fatalf("pow_response nonce is not an integer: %v", err)
	}
	p := ArgonParams{
		memory: 64, iterations: 1, parallelism: uint8(*parallelism),
		keyLength: uint32(*length), difficulty: 1, prefix: "prefix", salt: "salt",
	}
	if !p.Check(nonce) {
		t.Errorf("submitted nonce %d does not satisfy the challenge", nonce)
	}
}

func TestSaveLoadCookiesRoundTrip(t *testing.T) {
	// --cookie-jar / --cookie let a later invocation reuse a session (e.g.
	// established by a plain GET) for a POST that needs a matching CSRF
	// token + session cookie. Verify the round trip preserves name/value.
	u, err := url.Parse("https://example.onion/")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	saveJar, _ := cookiejar.New(nil)
	saveJar.SetCookies(u, []*http.Cookie{
		{Name: "xf_session", Value: "abc123"},
		{Name: "ttrs_clearance", Value: "def456"},
	})

	path := filepath.Join(t.TempDir(), "cookies.json")
	if err := saveCookies(path, saveJar, u); err != nil {
		t.Fatalf("saveCookies: %v", err)
	}

	loadJar, _ := cookiejar.New(nil)
	if err := loadCookies(path, loadJar, u); err != nil {
		t.Fatalf("loadCookies: %v", err)
	}

	got := map[string]string{}
	for _, c := range loadJar.Cookies(u) {
		got[c.Name] = c.Value
	}
	want := map[string]string{"xf_session": "abc123", "ttrs_clearance": "def456"}
	for name, wantVal := range want {
		if got[name] != wantVal {
			t.Errorf("cookie %q = %q, want %q", name, got[name], wantVal)
		}
	}
	if len(got) != len(want) {
		t.Errorf("loaded %d cookies, want %d (%v)", len(got), len(want), got)
	}
}

func TestSolveTartarusFlow(t *testing.T) {
	// Reproduce the real urlscan flow from
	// https://urlscan.io/api/v1/result/019c307d-9f9d-72ac-a600-a6319d5708d7/
	const (
		wantSalt = "a92a106fa4e8c2398ebcabecefebf28c_69853ed8"
		wantDiff = "16"
	)

	challengeHTML := fmt.Sprintf(
		`<html data-ttrs-challenge="%s" data-ttrs-difficulty="%s"></html>`,
		wantSalt, wantDiff)

	var gotPost url.Values
	var gotAccept, gotReferer, gotContentType string

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			// First GET returns 203 with challenge page.
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprint(w, challengeHTML)
		case r.Method == "POST" && r.URL.Path == "/.ttrs/challenge":
			// Capture the POST for assertions.
			body, _ := io.ReadAll(r.Body)
			gotPost, _ = url.ParseQuery(string(body))
			gotAccept = r.Header.Get("Accept")
			gotReferer = r.Header.Get("Referer")
			gotContentType = r.Header.Get("Content-Type")
			// Set a cookie like the real server does.
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test"})
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"success":true}`)
		case r.Method == "GET" && r.URL.Path == "/" && r.Header.Get("Cookie") != "":
			// Re-GET after challenge solved.
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>real page</html>")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	// Use the test server's client (trusts its TLS cert) with a cookie jar.
	jar, _ := cookiejar.New(nil)
	testClient := ts.Client()
	testClient.Jar = jar
	tc := &TorClient{c: *testClient}
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	resp.Body.Close()

	// Verify POST fields match the real urlscan capture.
	if got := gotPost.Get("salt"); got != wantSalt {
		t.Errorf("POST salt = %q, want %q", got, wantSalt)
	}
	if gotNonce := gotPost.Get("nonce"); gotNonce == "" {
		t.Error("POST nonce is empty")
	} else {
		n, err := strconv.Atoi(gotNonce)
		if err != nil {
			t.Errorf("POST nonce %q is not an integer: %v", gotNonce, err)
		} else {
			p := TartarusParams{salt: wantSalt, difficulty: 16}
			if !p.Check(n) {
				t.Errorf("POST nonce %d does not satisfy difficulty 16", n)
			}
		}
	}
	// The challenge POST is a fetch() from the interstitial's script, and a
	// browser sends Accept: */* for that -- application/json is a tell that no
	// browser produced the request.
	if gotAccept != "*/*" {
		t.Errorf("POST Accept = %q, want %q", gotAccept, "*/*")
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("POST Content-Type = %q, want %q", gotContentType, "application/x-www-form-urlencoded")
	}
	if gotReferer == "" {
		t.Error("POST Referer is empty, want original page URL")
	}
}

// newTestClient builds a TorClient backed by the test server's TLS client,
// with a cookie jar and manual redirect handling matching production.
func newTestClient(ts *httptest.Server) *TorClient {
	jar, _ := cookiejar.New(nil)
	c := ts.Client()
	c.Jar = jar
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &TorClient{c: *c}
}

// setMethod overrides the global --method flag for a test, returning a
// restore function intended for defer.
func setMethod(m string) func() {
	old := *method
	*method = m
	return func() { *method = old }
}

func TestFetchMethodHEAD(t *testing.T) {
	var gotMethod string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.Header().Set("X-Test", "present")
		w.WriteHeader(http.StatusOK)
		if r.Method != "HEAD" {
			fmt.Fprint(w, "body content")
		}
	}))
	defer ts.Close()
	defer setMethod("HEAD")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != "HEAD" {
		t.Errorf("server saw method %q, want HEAD", gotMethod)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Test") != "present" {
		t.Errorf("missing X-Test header on HEAD response")
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("HEAD body = %q, want empty", body)
	}
}

func TestFetchReturnsNonOKBody(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "the page was not found")
	}))
	defer ts.Close()
	defer setMethod("GET")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	body, err := decodeBody(resp)
	if err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	if string(body) != "the page was not found" {
		t.Errorf("body = %q, want the 404 page content", body)
	}
}

func TestFetchHEADThroughTartarus(t *testing.T) {
	// A HEAD request to a Tartarus-protected page must solve the challenge
	// (which requires fetching the HTML body via GET) and then re-issue the
	// destination request as HEAD once the clearance cookie is set.
	const (
		wantSalt = "a92a106fa4e8c2398ebcabecefebf28c_69853ed8"
		wantDiff = "16"
	)
	challengeHTML := fmt.Sprintf(
		`<html data-ttrs-challenge="%s" data-ttrs-difficulty="%s"></html>`,
		wantSalt, wantDiff)

	var clearedMethods []string
	var solvedWithGET bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.ttrs/challenge" && r.Method == "POST":
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"success":true}`)
		case r.URL.Path == "/":
			if _, err := r.Cookie("ttrs_clearance"); err != nil {
				// Not yet cleared: serve the challenge. The body is only
				// populated for GET (the HTTP server drops bodies on HEAD).
				if r.Method == "GET" {
					solvedWithGET = true
				}
				w.WriteHeader(http.StatusNonAuthoritativeInfo)
				fmt.Fprint(w, challengeHTML)
				return
			}
			// Cleared: record which method reached the destination.
			clearedMethods = append(clearedMethods, r.Method)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>real page</html>")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	defer setMethod("HEAD")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !solvedWithGET {
		t.Error("challenge body was never fetched with GET")
	}
	// Safety property: once clearance is established, the destination must be
	// reached ONLY via HEAD. A single GET here would download the resource
	// body — exactly what a HEAD probe exists to avoid (e.g. probing a path
	// the caller must not fetch). So assert NO cleared request used GET, not
	// merely that the last one was HEAD.
	if len(clearedMethods) == 0 {
		t.Error("destination was never reached after clearance")
	}
	for _, m := range clearedMethods {
		if m != "HEAD" {
			t.Errorf("cleared destination reached with %q; a HEAD probe must never fetch the body (methods = %v)", m, clearedMethods)
		}
	}
}

func TestFetchPOSTThroughTartarus(t *testing.T) {
	// A POST body (e.g. a search form submission) must survive a Tartarus
	// challenge round trip: the challenge itself is solved with a bodyless
	// GET, but the destination request re-issued after clearance must carry
	// the original POST body and its form Content-Type.
	const (
		wantSalt = "a92a106fa4e8c2398ebcabecefebf28c_69853ed8"
		wantDiff = "16"
		wantBody = "keywords=example&c%5Busers%5D=someuser"
	)
	challengeHTML := fmt.Sprintf(
		`<html data-ttrs-challenge="%s" data-ttrs-difficulty="%s"></html>`,
		wantSalt, wantDiff)

	var gotBody, gotContentType string
	var gotMethod string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.ttrs/challenge" && r.Method == "POST":
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"success":true}`)
		case r.URL.Path == "/search/search":
			if _, err := r.Cookie("ttrs_clearance"); err != nil {
				// Not yet cleared: serve the challenge (bodyless probe is fine
				// here, only GET can read this body per the existing flow).
				w.WriteHeader(http.StatusNonAuthoritativeInfo)
				fmt.Fprint(w, challengeHTML)
				return
			}
			// Cleared: record what reached the destination.
			gotMethod = r.Method
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			gotContentType = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>results</html>")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	defer setMethod("POST")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/search/search", "", []byte(wantBody))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if gotMethod != "POST" {
		t.Errorf("destination reached with method %q, want POST", gotMethod)
	}
	if gotBody != wantBody {
		t.Errorf("destination body = %q, want %q", gotBody, wantBody)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("destination Content-Type = %q, want application/x-www-form-urlencoded", gotContentType)
	}
}

func TestFetchPOSTThroughAPIStyleTartarusChallenge(t *testing.T) {
	// Some endpoints (observed live against a XenForo /search/search POST)
	// answer an unsolved request with 401 + a Www-Authenticate header
	// pointing at a separate challenge_url, instead of serving the classic
	// 203/HTML interstitial on the target itself. The salt/difficulty must
	// be read from that separate URL, and the retry after clearance must
	// still hit the ORIGINAL target (with its original method/body), not
	// the challenge endpoint.
	const (
		wantSalt = "a92a106fa4e8c2398ebcabecefebf28c_69853ed8"
		wantDiff = "16"
		wantBody = "keywords=example&c%5Busers%5D=someuser"
	)
	challengeHTML := fmt.Sprintf(
		`<html data-ttrs-challenge="%s" data-ttrs-difficulty="%s"></html>`,
		wantSalt, wantDiff)

	var gotChallengeURLMethod string
	var gotBody, gotContentType string
	var gotDestMethod string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.ttrs/challenge" && r.Method == "GET":
			gotChallengeURLMethod = r.Method
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprint(w, challengeHTML)
		case r.URL.Path == "/.ttrs/challenge" && r.Method == "POST":
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"success":true}`)
		case r.URL.Path == "/search/search":
			if _, err := r.Cookie("ttrs_clearance"); err != nil {
				w.Header().Set("Www-Authenticate", `Tartarus realm="challenge", challenge_url="/.ttrs/challenge"`)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"challenge_required","challenge_url":"/.ttrs/challenge"}`)
				return
			}
			gotDestMethod = r.Method
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			gotContentType = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html>results</html>")
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	defer setMethod("POST")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/search/search", "", []byte(wantBody))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if gotChallengeURLMethod != "GET" {
		t.Error("challenge_url was never GET'd to read the salt/difficulty")
	}
	if gotDestMethod != "POST" {
		t.Errorf("destination reached with method %q, want POST", gotDestMethod)
	}
	if gotBody != wantBody {
		t.Errorf("destination body = %q, want %q", gotBody, wantBody)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("destination Content-Type = %q, want application/x-www-form-urlencoded", gotContentType)
	}
}

func TestFetchHEADRefusesForbidden(t *testing.T) {
	// A HEAD that draws a 403 must NOT fall back to a GET of the target: that
	// GET can return the resource body (a 403 is intermittent / indistinguish-
	// able from a real Forbidden, and the "challenge" body may actually be the
	// file). So Fetch must error out without ever GETing the target.
	var sawGET bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == "GET" {
			// If the guard were missing, the fallback GET would land here and
			// the body would be downloaded. The resource leaks on GET.
			sawGET = true
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "RESOURCE BODY THAT MUST NOT BE FETCHED")
			return
		}
		// HEAD (and anything else) → 403.
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()
	defer setMethod("HEAD")()

	tc := newTestClient(ts)
	_, err := tc.Fetch(ts.URL+"/", "", nil)
	if err == nil {
		t.Fatal("expected an error refusing the 403 challenge in HEAD mode, got nil")
	}
	if sawGET {
		t.Error("a GET reached the target after a 403 HEAD — must never fall back to a body-fetching GET")
	}
}

func TestArgonCheck(t *testing.T) {
	// Use minimal parameters so the test runs quickly.
	p := ArgonParams{
		memory:      64,
		iterations:  1,
		parallelism: 1,
		keyLength:   32,
		difficulty:  0,
		prefix:      "test",
		salt:        "salt",
	}
	// difficulty=0 means 0 leading hex nibbles required, so any hash passes.
	if !p.Check(0) {
		t.Error("ArgonParams with difficulty=0 should accept any nonce")
	}
}
