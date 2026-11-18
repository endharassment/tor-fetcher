package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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
		// The step count doesn't change what a browser computes (challenge.js
		// ignores it), so any well-formed count parses; a malformed one means
		// the challenge shape changed and must not.
		{"multi-step challenge", `<html data-ttrs-challenge="abc" data-ttrs-difficulty="16" data-ttrs-steps="3">`, true, "abc", 16},
		{"malformed step count", `<html data-ttrs-challenge="abc" data-ttrs-difficulty="16" data-ttrs-steps="banana">`, false, "", 0},
		{"zero step count", `<html data-ttrs-challenge="abc" data-ttrs-difficulty="16" data-ttrs-steps="0">`, false, "", 0},
		{"json unsupported algorithm", `{"salt":"abc","difficulty":16,"algorithm":"argon2id"}`, false, "", 0},
		{"json multi-step challenge", `{"salt":"abc","difficulty":16,"steps":5}`, true, "abc", 16},
		{"json multi-step challenge, string steps", `{"salt":"abc","difficulty":16,"steps":"5"}`, true, "abc", 16},
		{"json malformed steps", `{"salt":"abc","difficulty":16,"steps":"x"}`, false, "", 0},
		{"json steps=1 is fine", `{"salt":"abc","difficulty":16,"steps":1,"algorithm":"sha256"}`, true, "abc", 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parseTartarusChallenge(tt.body)
			ok := err == nil
			if ok != tt.wantOK {
				t.Fatalf("parseTartarusChallenge() err = %v, want ok = %v", err, tt.wantOK)
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

// pinStartNonce makes the nonce search start at n for the rest of the test,
// so tests can predict which nonces the solver submits.
func pinStartNonce(t *testing.T, n int) {
	t.Helper()
	old := tartarusStartNonce
	tartarusStartNonce = func() int { return n }
	t.Cleanup(func() { tartarusStartNonce = old })
}

func TestFetchStepCountHandling(t *testing.T) {
	// Tartarus can advertise data-ttrs-steps > 1. The current challenge.js
	// ignores the step count and submits one SHA-256
	// nonce at the advertised difficulty, so we must solve it the same way.
	// A malformed count still means an unknown shape: no nonce may be
	// submitted, and the full body must survive into the error (a truncated
	// error once destroyed the only production evidence).
	const salt = "eeee5555eeee5555eeee5555eeee5555_55555555_16"
	tests := []struct {
		name      string
		steps     string
		wantPosts int
		wantErr   []string // nil: success
	}{
		{name: "single step", steps: "1", wantPosts: 1},
		{name: "multi-step solved as one nonce", steps: "3", wantPosts: 1},
		{name: "five steps", steps: "5", wantPosts: 1},
		{name: "malformed step count", steps: "banana", wantPosts: 0, wantErr: []string{salt, `"banana"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challengeHTML := fmt.Sprintf(
				`<html id="ttrs" class="no-js no-scripts" data-ttrs-challenge=%q data-ttrs-difficulty="16" data-ttrs-steps=%q data-ttrs-algorithm="sha256" data-ttrs-worker-v="ee91eb68">`,
				salt, tt.steps)
			var posts []url.Values
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == "POST" && r.URL.Path == "/.ttrs/challenge":
					body, _ := io.ReadAll(r.Body)
					v, _ := url.ParseQuery(string(body))
					posts = append(posts, v)
					http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "ok", Path: "/"})
					fmt.Fprint(w, `{"success":true}`)
				case r.URL.Path == "/.ttrs/challenge":
					w.WriteHeader(http.StatusNotFound)
				case r.Header.Get("Cookie") != "":
					fmt.Fprint(w, "<html>real page</html>")
				default:
					w.WriteHeader(http.StatusNonAuthoritativeInfo)
					fmt.Fprint(w, challengeHTML)
				}
			}))
			defer ts.Close()
			defer setMethod("GET")()

			resp, err := newTestClient(ts).Fetch(ts.URL+"/", "", nil)
			if len(posts) != tt.wantPosts {
				t.Errorf("challenge POSTs = %d, want %d", len(posts), tt.wantPosts)
			}
			if tt.wantErr != nil {
				if err == nil {
					resp.Body.Close()
					t.Fatal("expected an error, got nil")
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			resp.Body.Close()
			n, err := strconv.Atoi(posts[0].Get("nonce"))
			if err != nil || !(TartarusParams{salt: salt, difficulty: 16}).Check(n) {
				t.Errorf("submitted nonce %q is not a valid single SHA-256 solution at difficulty 16", posts[0].Get("nonce"))
			}
		})
	}
}

func TestTartarusNonceStartsLikeABrowser(t *testing.T) {
	// challenge.js starts at floor(random * MAX_SAFE_INTEGER); a search from
	// 0 would submit conspicuously small nonces.
	var large int
	for range 100 {
		n := tartarusStartNonce()
		if n < 0 || n >= maxSafeInteger {
			t.Fatalf("start nonce %d outside [0, MAX_SAFE_INTEGER)", n)
		}
		if n > 1<<40 {
			large++
		}
	}
	if large < 90 {
		t.Errorf("only %d/100 start nonces exceed 2^40; expected a uniform draw over [0, 2^53)", large)
	}

	// The solver searches upward from that start.
	start := 1<<52 + 12345
	pinStartNonce(t, start)
	const salt = "a92a106fa4e8c2398ebcabecefebf28c_69853ed8"
	var got string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST":
			body, _ := io.ReadAll(r.Body)
			v, _ := url.ParseQuery(string(body))
			got = v.Get("nonce")
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "ok", Path: "/"})
			fmt.Fprint(w, `{"success":true}`)
		case r.Header.Get("Cookie") != "":
			fmt.Fprint(w, "<html>real page</html>")
		default:
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprintf(w, `<html data-ttrs-challenge=%q data-ttrs-difficulty="16"></html>`, salt)
		}
	}))
	defer ts.Close()
	defer setMethod("GET")()
	resp, err := newTestClient(ts).Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	resp.Body.Close()
	n, err := strconv.Atoi(got)
	if err != nil || n < start || !(TartarusParams{salt: salt, difficulty: 16}).Check(n) {
		t.Errorf("submitted nonce %q, want a valid solution >= %d", got, start)
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
	// The challenge POST is an XHR whose script explicitly sets
	// Accept: application/json (challenge.js v=98eec8c2).
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

func TestSolveTartarusPOSTFailureIncludesDiagnostics(t *testing.T) {
	// A production failure once surfaced only as "tartarus challenge POST
	// returned 400" -- no salt, difficulty, nonce, or response body, so
	// there was nothing to diagnose after the fact. A wrong-but-locally-
	// valid-looking nonce is exactly what a steps>1 challenge parsed under
	// the steps=1 assumption would produce, so the failure message must
	// carry enough to tell that apart from other causes (stale salt, clock
	// skew, etc).
	const (
		wantSalt = "a92a106fa4e8c2398ebcabecefebf28c_69853ed8"
		wantDiff = "16"
	)
	challengeHTML := fmt.Sprintf(
		`<html data-ttrs-challenge="%s" data-ttrs-difficulty="%s"></html>`,
		wantSalt, wantDiff)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprint(w, challengeHTML)
		case r.Method == "POST" && r.URL.Path == "/.ttrs/challenge":
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"challenge expired"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	defer setMethod("GET")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error when the challenge POST is rejected, got nil")
	}
	msg := err.Error()
	for _, want := range []string{wantSalt, wantDiff, "400", "challenge expired"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not contain %q", msg, want)
		}
	}
}

func TestSolveTartarusRetriesSameSaltBeforeFetchingFresh(t *testing.T) {
	// These tests enumerate valid nonces from 0 to predict submissions.
	pinStartNonce(t, 0)
	// Reproduced live: a challenge salt handed to more than one concurrent
	// requester is only redeemable by the first submission; the rest get
	// {"success":false,"reason":"invalid_solution","action":"retry"}. Also
	// confirmed live: server-side rejection is scoped to the specific
	// (salt, nonce) pair, not the salt as a whole -- an independently valid
	// nonce for the SAME salt redeems fine. So the retry should continue
	// brute-forcing the same salt for the next valid nonce first, which
	// costs no extra network round trip, rather than fetching a fresh
	// challenge on the very first rejection.
	const (
		salt     = "aaaa1111aaaa1111aaaa1111aaaa1111_11111111_16"
		wantDiff = 16
	)
	p := TartarusParams{salt: salt, difficulty: wantDiff}
	var firstNonce int
	for n := 0; ; n++ {
		if p.Check(n) {
			firstNonce = n
			break
		}
	}

	var postCount, challengeEndpointGETs int
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			if _, err := r.Cookie("ttrs_clearance"); err == nil {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "<html>real page</html>")
				return
			}
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprintf(w, `<html data-ttrs-challenge=%q data-ttrs-difficulty="%d"></html>`, salt, wantDiff)
		case r.Method == "GET" && r.URL.Path == "/.ttrs/challenge":
			challengeEndpointGETs++
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"salt":%q,"difficulty":%d}`, salt, wantDiff)
		case r.Method == "POST" && r.URL.Path == "/.ttrs/challenge":
			postCount++
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("salt") != salt {
				t.Errorf("POST salt = %q, want the same salt %q throughout", form.Get("salt"), salt)
			}
			nonce, _ := strconv.Atoi(form.Get("nonce"))
			if nonce == firstNonce {
				// Simulate losing the race on the first-found nonce.
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"success":false,"reason":"invalid_solution","action":"retry"}`)
				return
			}
			// Any other independently-valid nonce for the same salt redeems.
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test", Path: "/"})
			fmt.Fprint(w, `{"success":true}`)
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

	if postCount != 2 {
		t.Errorf("challenge POST count = %d, want 2 (one lost race, one same-salt retry that won)", postCount)
	}
	if challengeEndpointGETs != 0 {
		t.Errorf("challenge endpoint GET count = %d, want 0 -- a same-salt retry shouldn't need a fresh challenge fetch", challengeEndpointGETs)
	}
	body, err := decodeBody(resp)
	if err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	if string(body) != "<html>real page</html>" {
		t.Errorf("body = %q, want the real page", body)
	}
}

func TestSolveTartarusFallsBackToFreshChallengeAfterSameSaltRetries(t *testing.T) {
	// If a salt keeps getting rejected across tartarusMaxSameSaltRetries
	// consecutive nonces, something other than an ordinary race may be
	// going on (e.g. the salt itself expired), so the remaining attempts
	// should escalate to fetching an entirely fresh challenge rather than
	// exhausting the whole budget on one salt.
	const (
		staleSalt = "aaaa1111aaaa1111aaaa1111aaaa1111_11111111_16"
		freshSalt = "bbbb2222bbbb2222bbbb2222bbbb2222_22222222_16"
		wantDiff  = 16
	)

	var postCount int
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			if _, err := r.Cookie("ttrs_clearance"); err == nil {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "<html>real page</html>")
				return
			}
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprintf(w, `<html data-ttrs-challenge=%q data-ttrs-difficulty="%d"></html>`, staleSalt, wantDiff)
		case r.Method == "GET" && r.URL.Path == "/.ttrs/challenge":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"salt":%q,"difficulty":%d}`, freshSalt, wantDiff)
		case r.Method == "POST" && r.URL.Path == "/.ttrs/challenge":
			postCount++
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("salt") == staleSalt {
				// staleSalt is permanently unredeemable, no matter the nonce.
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"success":false,"reason":"invalid_solution","action":"retry"}`)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test", Path: "/"})
			fmt.Fprint(w, `{"success":true}`)
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

	// tartarusMaxSameSaltRetries (2) rejections on staleSalt, plus the
	// initial attempt, then one more on the fresh salt that succeeds.
	if want := tartarusMaxSameSaltRetries + 2; postCount != want {
		t.Errorf("challenge POST count = %d, want %d", postCount, want)
	}
	body, err := decodeBody(resp)
	if err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	if string(body) != "<html>real page</html>" {
		t.Errorf("body = %q, want the real page", body)
	}
}

func TestSolveTartarusKeepsAdvancingWhenFreshChallengeMatchesSameSalt(t *testing.T) {
	// These tests enumerate valid nonces from 0 to predict submissions.
	pinStartNonce(t, 0)
	// Observed live in production: the fallback "fresh challenge" fetch can
	// come back with the SAME salt as before (the challenge endpoint's salt
	// is itself coarsely time-bucketed, and a whole retry sequence can
	// complete inside one bucket). If solveTartarus blindly restarted the
	// nonce search from 0 in that case, it would resubmit the exact nonce
	// that already lost -- wasting the final attempt on a submission that's
	// certain to fail again. It must instead keep advancing the same search.
	const (
		salt     = "aaaa1111aaaa1111aaaa1111aaaa1111_11111111_16"
		wantDiff = 16
	)
	p := TartarusParams{salt: salt, difficulty: wantDiff}
	var validNonces []int
	for n := 0; len(validNonces) < 4; n++ {
		if p.Check(n) {
			validNonces = append(validNonces, n)
		}
	}

	var submittedNonces []int
	var challengeEndpointGETs int
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			if _, err := r.Cookie("ttrs_clearance"); err == nil {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "<html>real page</html>")
				return
			}
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprintf(w, `<html data-ttrs-challenge=%q data-ttrs-difficulty="%d"></html>`, salt, wantDiff)
		case r.Method == "GET" && r.URL.Path == "/.ttrs/challenge":
			challengeEndpointGETs++
			// The "fresh" challenge is, infuriatingly, the SAME salt.
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"salt":%q,"difficulty":%d}`, salt, wantDiff)
		case r.Method == "POST" && r.URL.Path == "/.ttrs/challenge":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			nonce, _ := strconv.Atoi(form.Get("nonce"))
			submittedNonces = append(submittedNonces, nonce)
			// Only the 4th distinct valid nonce redeems -- forces the
			// fallback tier to fire and prove it doesn't repeat nonce[0].
			if nonce != validNonces[3] {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"success":false,"reason":"invalid_solution","action":"retry"}`)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "test", Path: "/"})
			fmt.Fprint(w, `{"success":true}`)
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

	if challengeEndpointGETs != 1 {
		t.Errorf("challenge endpoint GET count = %d, want 1 (the fallback tier firing once)", challengeEndpointGETs)
	}
	if len(submittedNonces) != len(validNonces) {
		t.Fatalf("submitted %d nonces, want %d: %v", len(submittedNonces), len(validNonces), submittedNonces)
	}
	for i, want := range validNonces {
		if submittedNonces[i] != want {
			t.Errorf("submitted nonce[%d] = %d, want %d (the search must keep advancing, not restart at nonce[0] after the same-salt fallback fetch): all submitted = %v",
				i, submittedNonces[i], want, submittedNonces)
		}
	}
}

func TestSolveTartarusGivesUpAfterMaxRetries(t *testing.T) {
	// A challenge that's rejected for a reason other than a resolvable race
	// must still fail loudly rather than retrying forever.
	const wantDiff = 16

	var postCount int
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprintf(w, `<html data-ttrs-challenge="cccc3333cccc3333cccc3333cccc3333_33333333_16" data-ttrs-difficulty="%d"></html>`, wantDiff)
		case r.Method == "GET" && r.URL.Path == "/.ttrs/challenge":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"salt":"dddd4444dddd4444dddd4444dddd4444_44444444_16","difficulty":%d}`, wantDiff)
		case r.Method == "POST" && r.URL.Path == "/.ttrs/challenge":
			postCount++
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"success":false,"reason":"invalid_solution","action":"retry"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()
	defer setMethod("GET")()

	tc := newTestClient(ts)
	resp, err := tc.Fetch(ts.URL+"/", "", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error when every retry is also rejected, got nil")
	}
	if postCount != tartarusMaxSolveAttempts {
		t.Errorf("challenge POST count = %d, want %d (bounded, not infinite)", postCount, tartarusMaxSolveAttempts)
	}
	if !strings.Contains(err.Error(), "invalid_solution") {
		t.Errorf("error %q does not contain the server's rejection reason", err.Error())
	}
}
