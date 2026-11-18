package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type ArgonParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
	difficulty  int
	prefix      string
	salt        string
}

func (p ArgonParams) Check(n int) bool {
	if p.difficulty == 0 {
		return true
	}
	password := fmt.Sprintf("%s%d", p.prefix, n)
	hash := argon2.IDKey([]byte(password), []byte(p.salt), p.iterations, p.memory, p.parallelism, p.keyLength)
	for i, v := range hash[:(p.difficulty+1)/2] {
		if 2*i == p.difficulty {
			return true
		}
		if v != 0 {
			if 2*i+1 == p.difficulty && v>>4 == 0 {
				return true
			}
			break
		}
	}
	return false
}

func (tc *TorClient) solveBasedFlare(requestURL *url.URL, body string) (*http.Response, error) {
	var p ArgonParams
	var pow string
	for _, l := range strings.Split(body, "\n") {
		// Match on the attribute rather than the line's exact indentation, so a
		// template whitespace change doesn't silently zero out the parameters.
		if !strings.Contains(l, "data-pow=") {
			continue
		}
		start := strings.Index(l, "<body ")
		if start == -1 {
			continue
		}
		attrs := l[start+len("<body "):]
		if end := strings.Index(attrs, ">"); end != -1 {
			attrs = attrs[:end]
		}

		for _, part := range strings.Fields(attrs) {
			key, value, found := strings.Cut(part, "=")
			if !found {
				continue
			}
			// Trim the quotes on either side of the value.
			value = strings.Trim(value, `"`)
			switch key {
			case "data-pow":
				pow = value
				params := strings.Split(pow, "#")
				if len(params) != 2 {
					return nil, fmt.Errorf("malformed basedflare data-pow %q, want salt#prefix", pow)
				}
				p.salt = params[0]
				p.prefix = params[1]
			case "data-time":
				iters, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("parsing basedflare time: %w", err)
				}
				p.iterations = uint32(iters)
			case "data-diff":
				bits, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("parsing basedflare diff: %w", err)
				}
				p.difficulty = bits / 8
			case "data-kb":
				mem, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("parsing basedflare kb: %w", err)
				}
				p.memory = uint32(mem)
			default:
				// Tolerate attributes we don't consume (class, onload, ...);
				// the completeness check below is what guards correctness.
				slog.Debug("ignoring basedflare body attribute", "key", key, "value", value)
			}
		}
		p.parallelism = uint8(*parallelism)
		p.keyLength = uint32(*length)
		break
	}

	// Refuse to "solve" a challenge we couldn't read. With zero parameters
	// difficulty is 0, which Check() accepts at nonce 0, so submitting anyway
	// posts a garbage pow_response that the server rejects far from the cause.
	if pow == "" || p.iterations == 0 || p.memory == 0 {
		return nil, fmt.Errorf("incomplete BasedFlare challenge parameters (pow=%q time=%d kb=%d diff=%d); body starts: %.200q",
			pow, p.iterations, p.memory, p.difficulty, body)
	}

	// Run the POW, single-threaded in case another circuit is running.
	var result int
	for n := 0; ; n++ {
		if p.Check(n) {
			result = n
			break
		}
	}

	// Post the result back to the checker.
	values := url.Values{}
	values.Set("pow_response", fmt.Sprintf("%s#%d", pow, result))
	values.Set("submit", "submit")
	return tc.PostForm(requestURL.String(), requestURL.String(), values)
}
