package main

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"testing"
)

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
