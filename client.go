package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

type TorClient struct {
	c http.Client
}

// do issues a request with the given method (GET, HEAD, POST, ...). reqBody
// is nil for bodyless requests; when non-empty it is sent as an
// application/x-www-form-urlencoded body (e.g. for -X POST -d "...").
func (tc *TorClient) do(method, target, referer string, reqBody []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if len(reqBody) > 0 {
		bodyReader = strings.NewReader(string(reqBody))
	}
	req, err := http.NewRequest(method, target, bodyReader)
	if err != nil {
		return nil, err
	}
	if len(reqBody) > 0 {
		// A request with a form body is a form submission, not a typed URL.
		setFormPostHeaders(req, req.URL, referer)
	} else {
		setHeaders(req, referer)
	}
	return tc.c.Do(req)
}

func (tc *TorClient) Get(target, referer string) (*http.Response, error) {
	return tc.do("GET", target, referer, nil)
}

func (tc *TorClient) PostForm(target, referer string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	setFormPostHeaders(req, req.URL, referer)
	return tc.c.Do(req)
}

func (tc *TorClient) Fetch(target, referer string, reqBody []byte) (*http.Response, error) {
	method := strings.ToUpper(*method)
	if method == "" {
		method = "GET"
	}
	currentURL := target
	currentReferer := referer

	// Challenges are always solved with GET (we need the HTML body and a
	// clearance cookie). finalize re-issues the destination request with the
	// caller's method (and body) once clearance is established. For plain
	// GET it is a no-op, so there is no extra round trip in the common case.
	finalize := func(resp *http.Response) (*http.Response, error) {
		if method == "GET" {
			return resp, nil
		}
		u := resp.Request.URL.String()
		ref := resp.Request.Header.Get("Referer")
		resp.Body.Close()
		tracef("%s %s (after clearance)", method, u)
		return tc.do(method, u, ref, reqBody)
	}

	for range 10 { // max redirect/challenge hops
		resp, err := tc.do(method, currentURL, currentReferer, reqBody)
		if err != nil {
			return nil, err
		}
		tracef("%s %s -> %d %s", method, currentURL, resp.StatusCode, http.StatusText(resp.StatusCode))

		// Follow redirects manually (we disabled auto-follow).
		if loc := resp.Header.Get("Location"); loc != "" &&
			(resp.StatusCode >= 300 && resp.StatusCode < 400) {
			resp.Body.Close()
			resolved, err := resp.Request.URL.Parse(loc)
			if err != nil {
				return nil, fmt.Errorf("bad redirect Location %q: %w", loc, err)
			}
			tracef("  -> redirect to %s", resolved)
			slog.Debug("following redirect", "from", currentURL, "to", resolved)
			currentReferer = currentURL
			currentURL = resolved.String()
			continue
		}

		// Not a challenge — return directly (with the caller's method).
		challengeURL := tartarusChallengeURL(resp)
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNonAuthoritativeInfo && challengeURL == nil {
			return resp, nil
		}

		// Body-safety for HEAD probes. Only a 203 Tartarus interstitial is safe
		// to resolve in HEAD mode: Tartarus consistently gates every unsolved
		// request, so the challenge-reading GET below returns the challenge
		// page, never the resource. A 403 is different — it is intermittent and
		// indistinguishable from a genuine Forbidden, and resolving it means
		// GETing the target to read a "challenge" body that may actually BE the
		// resource (downloading it). A HEAD probe exists precisely to avoid
		// fetching the body, so refuse a 403 outright rather than fall back to a
		// GET of the target. The caller can retry for a clean Tartarus-only pass.
		// (The 401 API-style challenge below is always safe: its GET target is
		// the dedicated /.ttrs/challenge endpoint, never the destination
		// resource, so there's nothing to leak.)
		if method == "HEAD" && resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return nil, fmt.Errorf("refusing to resolve a 403 challenge for a HEAD request: it would require a GET of the target that could download the body; retry for a Tartarus-only pass")
		}

		// The original target URL to retry once clearance is established.
		// Captured before chResp may point at a different challenge endpoint.
		requestURL := resp.Request.URL

		// Read the challenge body. Bodyless methods can't see it, and an
		// API-style 401 challenge carries the salt/difficulty on a separate
		// endpoint, not the response we already have — refetch with GET
		// whenever the challenge body isn't already what we're holding.
		fetchURL := currentURL
		if challengeURL != nil {
			fetchURL = challengeURL.String()
		}
		chResp := resp
		if method != "GET" || fetchURL != currentURL {
			resp.Body.Close()
			chResp, err = tc.do("GET", fetchURL, currentReferer, nil)
			if err != nil {
				return nil, err
			}
			tracef("GET %s -> %d %s (challenge body)", fetchURL, chResp.StatusCode, http.StatusText(chResp.StatusCode))
		}
		bodyBytes, err := decodeBody(chResp)
		chResp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading challenge body from %s: %w", fetchURL, err)
		}
		body := string(bodyBytes)

		// Identify the challenge by a POSITIVE match on each type. BasedFlare
		// must never be the fallback: solveBasedFlare parses no parameters out
		// of an unrecognized body, leaving difficulty 0, which Check() accepts
		// at nonce 0 — so an unknown challenge would silently POST a garbage
		// pow_response to the target instead of failing.
		p, parseErr := parseTartarusChallenge(body)
		switch {
		case parseErr == nil:
			tracef("  -> Tartarus challenge (difficulty=%d steps=%d)", p.difficulty, p.steps)
		case strings.Contains(body, "data-pow="):
			tracef("  -> BasedFlare challenge")
			bfResp, err := tc.solveBasedFlare(requestURL, body)
			if err != nil {
				return nil, err
			}
			return finalize(bfResp)
		default:
			var chErr error
			p, chErr = tc.tartarusChallengeParams(requestURL, currentReferer)
			if chErr != nil {
				return nil, fmt.Errorf("unrecognized %d challenge at %s: no BasedFlare parameters in the body; interstitial body unusable (%v); challenge endpoint also failed: %w; full interstitial body: %q",
					resp.StatusCode, fetchURL, parseErr, chErr, body)
			}
			tracef("  -> Tartarus challenge (difficulty=%d steps=%d, params from %s)", p.difficulty, p.steps, tartarusChallengePath)
		}

		challengeResp, err := tc.solveTartarus(method, requestURL, p, reqBody)
		if err != nil {
			return nil, err
		}
		// solveTartarus returns the re-GET response; loop to
		// handle further redirects or challenges on the new domain.
		if loc := challengeResp.Header.Get("Location"); loc != "" &&
			(challengeResp.StatusCode >= 300 && challengeResp.StatusCode < 400) {
			challengeResp.Body.Close()
			resolved, err := requestURL.Parse(loc)
			if err != nil {
				return nil, fmt.Errorf("bad redirect Location %q: %w", loc, err)
			}
			tracef("  -> redirect after challenge to %s", resolved)
			slog.Debug("following redirect after challenge", "from", requestURL, "to", resolved)
			currentReferer = requestURL.String()
			currentURL = resolved.String()
			continue
		}
		return finalize(challengeResp)
	}
	return nil, fmt.Errorf("too many redirects/challenges")
}
