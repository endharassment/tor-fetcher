package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

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
