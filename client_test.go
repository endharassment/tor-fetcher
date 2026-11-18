package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
)

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
