package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type TartarusParams struct {
	salt       string
	difficulty uint
}

func (p TartarusParams) Check(n int) bool {
	input := p.salt + strconv.Itoa(n)
	hash := sha256.Sum256([]byte(input))
	val := binary.BigEndian.Uint32(hash[:4])
	return val < (1 << (32 - p.difficulty))
}

// extractAttr extracts the value of an HTML attribute from a string.
// e.g. extractAttr(`<html data-foo="bar">`, "data-foo") returns "bar".
func extractAttr(s, attr string) string {
	key := attr + `="`
	idx := strings.Index(s, key)
	if idx == -1 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(s[start:], `"`)
	if end == -1 {
		return ""
	}
	return s[start : start+end]
}

// tartarusChallengePath is where Tartarus serves PoW parameters and accepts
// solutions. It is a dedicated endpoint, never a destination resource.
const tartarusChallengePath = "/.ttrs/challenge"

// checkTartarusCapability reports whether TartarusParams.Check can evaluate a
// challenge advertising the given algorithm/steps. Check implements exactly
// single-step SHA256 over salt+nonce, so anything else must be rejected
// explicitly: silently treating an unsupported algorithm or step count as
// sha256/steps=1 would submit a nonce that looks locally valid but is wrong
// -- a worse failure than refusing outright, since it burns a solve attempt
// (and a clearance-granting circuit) without any indication of why. Absent
// attributes mean the defaults, which are supported.
func checkTartarusCapability(algorithm, steps string) error {
	if algorithm != "" && algorithm != "sha256" {
		return fmt.Errorf("unsupported tartarus algorithm %q (only sha256 is implemented)", algorithm)
	}
	if steps != "" && steps != "1" {
		return fmt.Errorf("unsupported tartarus step count %q (only steps=1 is implemented)", steps)
	}
	return nil
}

// parseTartarusChallenge extracts the PoW salt and difficulty from a Tartarus
// challenge document. Two shapes are accepted: the HTML interstitial, which
// carries them as data-ttrs-* attributes, and the JSON object served by
// tartarusChallengePath. A non-nil error means either the document isn't a
// Tartarus challenge at all, or it is one but advertises PoW rules Check
// can't evaluate -- both must be treated the same way by the caller: don't
// submit a nonce.
func parseTartarusChallenge(body string) (TartarusParams, error) {
	if salt := extractAttr(body, "data-ttrs-challenge"); salt != "" {
		difficultyStr := extractAttr(body, "data-ttrs-difficulty")
		difficulty, err := strconv.Atoi(difficultyStr)
		if err != nil || difficulty <= 0 {
			return TartarusParams{}, fmt.Errorf("data-ttrs-challenge present but data-ttrs-difficulty is missing or invalid (%q)", difficultyStr)
		}
		if err := checkTartarusCapability(extractAttr(body, "data-ttrs-algorithm"), extractAttr(body, "data-ttrs-steps")); err != nil {
			return TartarusParams{}, err
		}
		return TartarusParams{salt: salt, difficulty: uint(difficulty)}, nil
	}

	var j struct {
		Salt       string `json:"salt"`
		Challenge  string `json:"challenge"`
		Difficulty any    `json:"difficulty"`
		Algorithm  string `json:"algorithm"`
		Steps      any    `json:"steps"`
	}
	if err := json.Unmarshal([]byte(body), &j); err != nil {
		return TartarusParams{}, fmt.Errorf("no data-ttrs-challenge attribute, and not JSON either: %w", err)
	}
	salt := j.Salt
	if salt == "" {
		salt = j.Challenge
	}
	var difficulty int
	switch d := j.Difficulty.(type) {
	case float64:
		difficulty = int(d)
	case string:
		difficulty, _ = strconv.Atoi(d)
	}
	if salt == "" || difficulty <= 0 {
		return TartarusParams{}, fmt.Errorf("JSON challenge missing salt/challenge or difficulty")
	}
	var steps string
	switch s := j.Steps.(type) {
	case float64:
		steps = strconv.Itoa(int(s))
	case string:
		steps = s
	}
	if err := checkTartarusCapability(j.Algorithm, steps); err != nil {
		return TartarusParams{}, err
	}
	return TartarusParams{salt: salt, difficulty: uint(difficulty)}, nil
}

// tartarusChallengeParams asks tartarusChallengePath for the PoW parameters
// directly. Interstitials that leave the salt/difficulty out of the HTML (the
// page's JS fetches them) are otherwise unsolvable. Safe in HEAD mode: the
// endpoint is never the destination resource, so it can't download the body a
// HEAD probe exists to avoid.
func (tc *TorClient) tartarusChallengeParams(requestURL *url.URL, referer string) (TartarusParams, error) {
	chURL := fmt.Sprintf("%s://%s%s", requestURL.Scheme, requestURL.Host, tartarusChallengePath)
	resp, err := tc.Get(chURL, referer)
	if err != nil {
		return TartarusParams{}, fmt.Errorf("fetching %s: %w", chURL, err)
	}
	body, err := decodeBody(resp)
	resp.Body.Close()
	tracef("GET %s -> %d %s (challenge params)", chURL, resp.StatusCode, http.StatusText(resp.StatusCode))
	if err != nil {
		return TartarusParams{}, fmt.Errorf("reading %s: %w", chURL, err)
	}
	p, err := parseTartarusChallenge(string(body))
	if err != nil {
		return TartarusParams{}, fmt.Errorf("no usable challenge parameters at %s (HTTP %d): %w; full body: %q",
			chURL, resp.StatusCode, err, body)
	}
	return p, nil
}

// tartarusChallengeURL reports the URL to GET for a Tartarus challenge's
// salt/difficulty when resp signals an API-style challenge via a 401 with a
// `Www-Authenticate: Tartarus ... challenge_url="..."` header — the shape
// used by XHR/form endpoints (e.g. a search POST), as opposed to the classic
// 203/403 page interstitial where the target itself IS the challenge page.
// Returns nil when resp isn't this kind of challenge.
func tartarusChallengeURL(resp *http.Response) *url.URL {
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}
	auth := resp.Header.Get("Www-Authenticate")
	if !strings.HasPrefix(auth, "Tartarus ") {
		return nil
	}
	loc := extractAttr(auth, "challenge_url")
	if loc == "" {
		return nil
	}
	resolved, err := resp.Request.URL.Parse(loc)
	if err != nil {
		return nil
	}
	return resolved
}

// tartarusMaxSolveAttempts bounds the retry-on-server-signal loop in
// solveTartarus: a rejected submission can carry an explicit action:"retry",
// and that's real, bounded, self-resolving signal rather than an unknown
// failure mode, so it's safe to retry automatically -- but bounded, so a
// challenge that's rejected for some other reason still fails loudly rather
// than looping.
const tartarusMaxSolveAttempts = 4

// tartarusMaxSameSaltRetries bounds how many of those retries continue
// brute-forcing the SAME salt for the next valid nonce, which is cheap (no
// extra network round trip): server-side rejection was confirmed live to be
// scoped to the specific (salt, nonce) pair, not the salt as a whole, so
// resuming the same search past a rejected nonce is normally enough. If it
// still isn't after a couple of tries, something else may be going on, so
// the remaining attempts escalate to fetching an entirely fresh challenge
// instead of exhausting the whole budget on a salt that might never redeem.
const tartarusMaxSameSaltRetries = 2

func (tc *TorClient) solveTartarus(method string, requestURL *url.URL, p TartarusParams, reqBody []byte) (*http.Response, error) {
	referer := requestURL.String()
	var lastErr error
	nextNonce := 0 // resume point for the current salt's brute-force search
	sameSaltRetries := 0
	for attempt := 1; attempt <= tartarusMaxSolveAttempts; attempt++ {
		// Brute-force SHA256 PoW, resuming past any nonce already rejected
		// for this salt rather than restarting from 0 (which would just
		// find that same rejected nonce again).
		var nonce int
		for n := nextNonce; ; n++ {
			if p.Check(n) {
				nonce = n
				break
			}
		}
		nextNonce = nonce + 1

		challengeURL := fmt.Sprintf("%s://%s%s", requestURL.Scheme, requestURL.Host, tartarusChallengePath)
		slog.Debug("tartarus challenge solved", "salt", p.salt, "difficulty", p.difficulty, "nonce", nonce, "attempt", attempt)

		// POST the solution. A 200 is not necessarily clearance: the server
		// can answer the PoW with a bandwidth offer ({"next":"bandwidth",...},
		// no Set-Cookie), in which case the same salt/nonce is re-POSTed with
		// the receipt the bandwidth stage earned. Mirrors challenge.js
		// (v=98eec8c2): success:true is clearance, a bandwidth offer is only
		// honoured on the first POST, and any other 200 is a rejection.
		receipt := ""
		var postResp *http.Response
		var postBody []byte
		for {
			var err error
			postResp, postBody, err = tc.postTartarusSolution(challengeURL, requestURL, p.salt, nonce, receipt)
			if err != nil {
				return nil, err
			}
			if postResp.StatusCode != http.StatusOK {
				break
			}
			var accepted struct {
				Success              bool   `json:"success"`
				Next                 string `json:"next"`
				Token                string `json:"token"`
				BandwidthSize        int64  `json:"bandwidth_size"`
				BandwidthTimeoutSecs int64  `json:"bandwidth_timeout_secs"`
			}
			if err := json.Unmarshal(postBody, &accepted); err != nil {
				return nil, fmt.Errorf("tartarus challenge POST to %s returned 200 with a non-JSON body (salt=%s nonce=%d): %q", challengeURL, p.salt, nonce, postBody)
			}
			if accepted.Success {
				if tc.c.Jar != nil {
					slog.Debug("tartarus jar cookies", "url", requestURL, "cookies", tc.c.Jar.Cookies(requestURL))
				}
				// Re-fetch the original target with the CALLER'S method and
				// body now that the ttrs_clearance cookie is set (the jar
				// preserves it). Using the caller's method rather than a
				// hardcoded GET means a HEAD probe never downloads the
				// destination body -- essential when the caller must learn a
				// resource's status without fetching the resource itself.
				return tc.do(method, requestURL.String(), requestURL.String(), reqBody)
			}
			if accepted.Next == "bandwidth" && receipt == "" {
				if accepted.Token == "" || accepted.BandwidthSize <= 0 || accepted.BandwidthSize > maxSafeInteger || accepted.BandwidthTimeoutSecs < 0 {
					return nil, fmt.Errorf("tartarus returned an invalid bandwidth offer (salt=%s nonce=%d): %q", p.salt, nonce, postBody)
				}
				receipt, err = tc.solveTartarusBandwidth(requestURL, accepted.Token, accepted.BandwidthSize, time.Duration(accepted.BandwidthTimeoutSecs)*time.Second)
				if err != nil {
					return nil, fmt.Errorf("tartarus bandwidth stage (salt=%s nonce=%d, offer %q): %w", p.salt, nonce, postBody, err)
				}
				continue
			}
			if accepted.Next != "" {
				// Leave room for future stages without silently re-GETting
				// back into the interstitial, which would look like a
				// rejected solve rather than an unimplemented stage.
				return nil, fmt.Errorf("tartarus PoW accepted but server requires an unsupported follow-up stage %q (salt=%s difficulty=%d nonce=%d, receipt sent=%t): response body: %q",
					accepted.Next, p.salt, p.difficulty, nonce, receipt != "", postBody)
			}
			return nil, fmt.Errorf("tartarus challenge POST to %s returned 200 without success (salt=%s difficulty=%d nonce=%d, receipt sent=%t): response body: %q",
				challengeURL, p.salt, p.difficulty, nonce, receipt != "", postBody)
		}

		lastErr = fmt.Errorf("tartarus challenge POST to %s returned %d (submitted salt=%s difficulty=%d nonce=%d, attempt %d/%d): response body: %q",
			challengeURL, postResp.StatusCode, p.salt, p.difficulty, nonce, attempt, tartarusMaxSolveAttempts, postBody)

		var reject struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(postBody, &reject); err != nil || reject.Action != "retry" || attempt == tartarusMaxSolveAttempts {
			break
		}

		if sameSaltRetries < tartarusMaxSameSaltRetries {
			sameSaltRetries++
			continue
		}
		newP, err := tc.tartarusChallengeParams(requestURL, referer)
		if err != nil {
			lastErr = fmt.Errorf("%w (fetching a fresh challenge to retry also failed: %v)", lastErr, err)
			break
		}
		// The "fresh" challenge can come back with the SAME salt (observed
		// live: the challenge endpoint's salt is itself coarsely time-
		// bucketed, and a whole retry sequence can complete inside one
		// bucket). Resetting the nonce search to 0 in that case would just
		// resubmit the exact nonce that already lost -- only restart the
		// search when the salt actually changed; otherwise keep advancing
		// through the same search we were already running.
		if newP.salt != p.salt {
			nextNonce = 0
			sameSaltRetries = 0
		}
		p = newP
	}
	return nil, lastErr
}

// postTartarusSolution POSTs a solved challenge to challengeURL as the
// interstitial's XHR does, with the bandwidth receipt appended when non-empty.
// The body is built by hand rather than with url.Values.Encode, which sorts
// keys: challenge.js sends salt, nonce, then bandwidth_receipt, and a
// reordered body is a needless tell.
func (tc *TorClient) postTartarusSolution(challengeURL string, page *url.URL, salt string, nonce int, receipt string) (*http.Response, []byte, error) {
	body := "salt=" + url.QueryEscape(salt) + "&nonce=" + strconv.Itoa(nonce)
	if receipt != "" {
		body += "&bandwidth_receipt=" + url.QueryEscape(receipt)
	}
	req, err := http.NewRequest("POST", challengeURL, strings.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("building tartarus POST: %w", err)
	}
	setXHRHeaders(req, page)
	resp, err := tc.c.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("posting tartarus solution: %w", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	tracef("POST %s -> %d %s (receipt=%t)", challengeURL, resp.StatusCode, http.StatusText(resp.StatusCode), receipt != "")
	slog.Debug("tartarus POST response", "status", resp.StatusCode, "body", string(respBody))
	slog.Debug("tartarus POST cookies", "set-cookie", resp.Header["Set-Cookie"])
	return resp, respBody, nil
}
