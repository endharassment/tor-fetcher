package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/coder/websocket"
)

// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER, the bound
// challenge.js enforces on bandwidth_size.
const maxSafeInteger = 1<<53 - 1

// tartarusBandwidthPath is the WebSocket endpoint for the bandwidth stage.
const tartarusBandwidthPath = "/.ttrs/captcha/bandwidth"

// tartarusBandwidthDefaultTimeout is challenge.js's fallback when the offer
// carries no bandwidth_timeout_secs.
const tartarusBandwidthDefaultTimeout = 120 * time.Second

// solveTartarusBandwidth runs the bandwidth stage Tartarus can chain after the
// PoW, and returns the receipt to re-POST alongside the solution. Protocol, as
// implemented by challenge-bandwidth.js (v=67a29b51):
//
//  1. Open wss://<host>/.ttrs/captcha/bandwidth?token=<offer token>&proof=sha256.
//  2. The server streams ~size bytes as binary messages. The client hashes
//     each MESSAGE separately with SHA-256 -- message boundaries are part of
//     the proof, so this can't be a running hash over the byte stream.
//  3. On a text {"status":"verify"}, send {"proof": hex(sha256(concatenated
//     per-message digests))}. (Without &proof=sha256 the browser uses
//     BLAKE2b-256 instead; we always claim WebCrypto.)
//  4. {"status":"ok","token":R,"next":"challenge"} yields receipt R;
//     {"status":"fail","message":...} is a rejection.
func (tc *TorClient) solveTartarusBandwidth(page *url.URL, token string, size int64, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = tartarusBandwidthDefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	scheme := "wss"
	if page.Scheme == "http" {
		scheme = "ws"
	}
	wsURL := fmt.Sprintf("%s://%s%s?token=%s&proof=sha256", scheme, page.Host, tartarusBandwidthPath, url.QueryEscape(token))

	// coder/websocket rejects a client with a Timeout set, and must not
	// follow redirects on a handshake; otherwise reuse our transport (Tor
	// Browser ClientHello, same SOCKS proxy) and cookie jar.
	hc := tc.c
	hc.Timeout = 0
	start := time.Now()
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient:      &hc,
		HTTPHeader:      webSocketHeaders(page),
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		return "", fmt.Errorf("dialing %s: %w", wsURL, err)
	}
	defer conn.CloseNow()
	// The whole payload may arrive as one message; allow it plus slack.
	conn.SetReadLimit(size + 1<<20)
	tracef("WS %s connected after %s; expecting %d bytes", tartarusBandwidthPath, time.Since(start).Round(time.Millisecond), size)

	var digests []byte
	var received int64
	var messages int
	proofSent := false
	nextReport := int64(4 << 20)
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return "", fmt.Errorf("bandwidth stream after %d/%d bytes in %d messages (%s): %w",
				received, size, messages, time.Since(start).Round(time.Millisecond), err)
		}
		if typ == websocket.MessageBinary {
			d := sha256.Sum256(data)
			digests = append(digests, d[:]...)
			received += int64(len(data))
			messages++
			if received >= nextReport {
				tracef("  bandwidth: %d/%d bytes after %s", received, size, time.Since(start).Round(time.Millisecond))
				nextReport += 4 << 20
			}
			continue
		}
		var msg struct {
			Status  string `json:"status"`
			Token   string `json:"token"`
			Next    string `json:"next"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			// challenge-bandwidth.js ignores unparseable text frames.
			slog.Debug("bandwidth: ignoring non-JSON text message", "data", string(data))
			continue
		}
		switch msg.Status {
		case "verify":
			if proofSent {
				continue
			}
			proofSent = true
			sum := sha256.Sum256(digests)
			proof, _ := json.Marshal(struct {
				Proof string `json:"proof"`
			}{hex.EncodeToString(sum[:])})
			tracef("  bandwidth: received %d bytes in %d messages after %s; sending proof",
				received, messages, time.Since(start).Round(time.Millisecond))
			if err := conn.Write(ctx, websocket.MessageText, proof); err != nil {
				return "", fmt.Errorf("sending bandwidth proof: %w", err)
			}
		case "ok":
			conn.Close(websocket.StatusNormalClosure, "")
			if msg.Next != "challenge" || msg.Token == "" {
				return "", fmt.Errorf("bandwidth stage did not return a receipt: %q", data)
			}
			tracef("  bandwidth: receipt after %s", time.Since(start).Round(time.Millisecond))
			return msg.Token, nil
		case "fail":
			return "", fmt.Errorf("bandwidth stage failed after %d/%d bytes: %q", received, size, data)
		default:
			slog.Debug("bandwidth: ignoring text message", "data", string(data))
		}
	}
}
