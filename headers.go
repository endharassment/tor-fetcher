package main

import (
	"net/http"
	"net/url"
	"strings"
)

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

// setXHRHeaders applies the headers an XMLHttpRequest from page JavaScript
// sends -- what Tartarus's challenge POST actually is. The default for an XHR
// would be Accept: */*, but challenge.js (v=98eec8c2) explicitly calls
// setRequestHeader('Accept','application/json'), so that is what Tor Browser
// sends. It carries an Origin.
func setXHRHeaders(req *http.Request, page *url.URL) {
	setCommonHeaders(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", formContentType)
	req.Header.Set("Origin", page.Scheme+"://"+page.Host)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Priority", "u=4")
	setReferer(req, page.String())
}

// webSocketHeaders returns the headers for a same-origin `new WebSocket()`
// handshake. The WebSocket library sets Connection/Upgrade/Sec-WebSocket-*
// itself (it offers a bare permessage-deflate, as Firefox does).
//
// NOT YET CAPTURED from Tor Browser, unlike setHeaders/setXHRHeaders: these
// follow the Fetch spec and Firefox's known WebSocket handshake (mode
// "websocket", no-cache pragma). Re-capture per CLAUDE.md before relying on
// them to blend in. Known difference: Firefox sends
// "Connection: keep-alive, Upgrade"; the library forces "Connection: Upgrade".
func webSocketHeaders(page *url.URL) http.Header {
	req := &http.Request{Header: http.Header{}}
	setCommonHeaders(req)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", page.Scheme+"://"+page.Host)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "websocket")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	return req.Header
}
