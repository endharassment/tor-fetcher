package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
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
	resp, err := tc.Fetch(ts.URL+"/", "")
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
	if gotAccept != "application/json" {
		t.Errorf("POST Accept = %q, want %q", gotAccept, "application/json")
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
	resp, err := tc.Fetch(ts.URL+"/", "")
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
	resp, err := tc.Fetch(ts.URL+"/", "")
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
	resp, err := tc.Fetch(ts.URL+"/", "")
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
