package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

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
