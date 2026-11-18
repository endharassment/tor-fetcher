package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

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
