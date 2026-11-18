package main

import (
	"net/http"
	"net/url"
	"testing"
)

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
			// The challenge POST is an XMLHttpRequest from page JS, and
			// challenge.js (v=98eec8c2) explicitly sets Accept:
			// application/json on it. It carries an Origin. Referer is suppressed because the page is
			// a .onion (network.http.referer.hideOnionSource).
			name:  "challenge POST is an XHR",
			build: func(r *http.Request) { setXHRHeaders(r, pageURL) },
			want: map[string]string{
				"User-Agent":      *ua,
				"Accept":          "application/json",
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
