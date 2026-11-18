package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/coder/websocket"
)

// newUTLSTestClient returns a TorClient that goes through utlsTransport (the
// production RoundTripper) rather than ts.Client(), dialing the test server
// with plain crypto/tls. This exercises the transport's own HTTP/1.1 path,
// including the 101 Upgrade hand-off the bandwidth WebSocket depends on.
func newUTLSTestClient(ts *httptest.Server) *TorClient {
	addr := ts.Listener.Addr().String()
	jar, _ := cookiejar.New(nil)
	return &TorClient{c: http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &utlsTransport{dialTLS: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
			return d.DialContext(ctx, network, addr)
		}},
	}}
}

// bandwidthServer simulates Tartarus's PoW + bandwidth flow as implemented by
// challenge.js (v=98eec8c2) and challenge-bandwidth.js (v=67a29b51), captured
// 2026-11-18. The knobs let each test break one step.
type bandwidthServer struct {
	offer        string   // 200 body for the first POST (no receipt)
	messages     [][]byte // binary messages streamed over the WebSocket
	wsResult     string   // text sent after a correct proof
	receiptReply string   // 200 body for the POST carrying the right receipt

	posts     []string    // raw POST bodies, in order
	wsHeader  http.Header // handshake request headers
	wsQuery   url.Values
	gotProof  string
	wantProof string
	gets      int
}

const bwSalt = "ca023ed548e1d49e7bf074941514ab1e_6afdbf43_8"

func (s *bandwidthServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/":
			s.gets++
			if c, err := r.Cookie("ttrs_clearance"); err == nil && c.Value == "ok" {
				fmt.Fprint(w, "<html>real page</html>")
				return
			}
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			fmt.Fprintf(w, `<html data-ttrs-challenge="%s" data-ttrs-difficulty="8" data-ttrs-steps="1" data-ttrs-algorithm="sha256"></html>`, bwSalt)
		case r.Method == "POST" && r.URL.Path == "/.ttrs/challenge":
			body, _ := io.ReadAll(r.Body)
			s.posts = append(s.posts, string(body))
			v, _ := url.ParseQuery(string(body))
			w.Header().Set("Content-Type", "application/json")
			switch v.Get("bandwidth_receipt") {
			case "":
				fmt.Fprint(w, s.offer)
			case "receipt-xyz":
				http.SetCookie(w, &http.Cookie{Name: "ttrs_clearance", Value: "ok", Path: "/"})
				fmt.Fprint(w, s.receiptReply)
			default:
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"success":false}`)
			}
		case r.URL.Path == "/.ttrs/captcha/bandwidth":
			s.wsHeader = r.Header.Clone()
			s.wsQuery = r.URL.Query()
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionContextTakeover})
			if err != nil {
				t.Errorf("websocket accept: %v", err)
				return
			}
			defer c.CloseNow()
			ctx := r.Context()
			var digests []byte
			for _, m := range s.messages {
				d := sha256.Sum256(m)
				digests = append(digests, d[:]...)
				if err := c.Write(ctx, websocket.MessageBinary, m); err != nil {
					t.Errorf("websocket write: %v", err)
					return
				}
			}
			sum := sha256.Sum256(digests)
			s.wantProof = hex.EncodeToString(sum[:])
			c.Write(ctx, websocket.MessageText, []byte(`not json, ignored`))
			c.Write(ctx, websocket.MessageText, []byte(`{"status":"verify"}`))
			_, data, err := c.Read(ctx)
			if err != nil {
				t.Errorf("websocket read proof: %v", err)
				return
			}
			var p struct {
				Proof string `json:"proof"`
			}
			json.Unmarshal(data, &p)
			s.gotProof = p.Proof
			if p.Proof != s.wantProof {
				c.Write(ctx, websocket.MessageText, []byte(`{"status":"fail","message":"bad proof"}`))
				return
			}
			c.Write(ctx, websocket.MessageText, []byte(s.wsResult))
			c.Read(ctx) // wait for the client's close
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
}

func defaultBandwidthServer() *bandwidthServer {
	// Uneven message sizes, so a proof computed over the byte stream rather
	// than per message would come out wrong.
	msgs := [][]byte{bytes.Repeat([]byte{1}, 1), bytes.Repeat([]byte{2}, 70000), bytes.Repeat([]byte{3}, 4096), {4, 5, 6}}
	var total int
	for _, m := range msgs {
		total += len(m)
	}
	return &bandwidthServer{
		offer:        fmt.Sprintf(`{"next":"bandwidth","token":"tok.en","bandwidth_size":%d,"bandwidth_timeout_secs":30}`, total),
		messages:     msgs,
		wsResult:     `{"status":"ok","token":"receipt-xyz","next":"challenge","expires_in":300}`,
		receiptReply: `{"success":true}`,
	}
}

func TestSolveTartarusBandwidthFlow(t *testing.T) {
	s := defaultBandwidthServer()
	ts := httptest.NewTLSServer(s.handler(t))
	defer ts.Close()
	defer setMethod("GET")()

	resp, err := newUTLSTestClient(ts).Fetch(ts.URL+"/", "", nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "<html>real page</html>" {
		t.Fatalf("got %d %q, want 200 real page", resp.StatusCode, body)
	}

	if s.gotProof != s.wantProof {
		t.Errorf("proof = %q, want %q", s.gotProof, s.wantProof)
	}
	if got := s.wsQuery.Get("token"); got != "tok.en" {
		t.Errorf("ws token = %q, want %q", got, "tok.en")
	}
	if got := s.wsQuery.Get("proof"); got != "sha256" {
		t.Errorf("ws proof = %q, want sha256", got)
	}
	for k, want := range map[string]string{
		"Origin":                   ts.URL,
		"Sec-Fetch-Mode":           "websocket",
		"Sec-Fetch-Dest":           "empty",
		"Sec-Fetch-Site":           "same-origin",
		"Sec-Websocket-Extensions": "permessage-deflate",
		"User-Agent":               *ua,
	} {
		if got := s.wsHeader.Get(k); got != want {
			t.Errorf("ws handshake %s = %q, want %q", k, got, want)
		}
	}

	// Both POSTs carry the same solution, in challenge.js's field order (not
	// url.Values.Encode's sorted order); only the second carries the receipt.
	if len(s.posts) != 2 {
		t.Fatalf("got %d challenge POSTs, want 2: %q", len(s.posts), s.posts)
	}
	first, second := s.posts[0], s.posts[1]
	if !strings.HasPrefix(first, "salt="+bwSalt+"&nonce=") || strings.Contains(first, "bandwidth_receipt") {
		t.Errorf("first POST body = %q, want salt=...&nonce=... with no receipt", first)
	}
	if second != first+"&bandwidth_receipt=receipt-xyz" {
		t.Errorf("second POST body = %q, want %q", second, first+"&bandwidth_receipt=receipt-xyz")
	}
	if s.gets != 2 {
		t.Errorf("GET / issued %d times, want 2 (interstitial, then cleared)", s.gets)
	}
}

func TestSolveTartarusBandwidthFailuresAreLoud(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*bandwidthServer)
		wantErr  []string
		wantGets int
	}{
		{
			name:     "unsupported follow-up stage",
			mutate:   func(s *bandwidthServer) { s.offer = `{"next":"pow2","token":"t"}` },
			wantErr:  []string{`unsupported follow-up stage "pow2"`, bwSalt},
			wantGets: 1,
		},
		{
			name:     "invalid bandwidth offer",
			mutate:   func(s *bandwidthServer) { s.offer = `{"next":"bandwidth","bandwidth_size":10}` },
			wantErr:  []string{"invalid bandwidth offer"},
			wantGets: 1,
		},
		{
			name:     "server reports failure after the proof",
			mutate:   func(s *bandwidthServer) { s.wsResult = `{"status":"fail","message":"too slow"}` },
			wantErr:  []string{"bandwidth stage failed", "too slow"},
			wantGets: 1,
		},
		{
			name:     "ok without a receipt",
			mutate:   func(s *bandwidthServer) { s.wsResult = `{"status":"ok","next":"challenge"}` },
			wantErr:  []string{"did not return a receipt"},
			wantGets: 1,
		},
		{
			name:     "receipt POST answered with another bandwidth offer",
			mutate:   func(s *bandwidthServer) { s.receiptReply = s.offer },
			wantErr:  []string{`unsupported follow-up stage "bandwidth"`, "receipt sent=true"},
			wantGets: 1,
		},
		{
			name:     "receipt POST answered without success",
			mutate:   func(s *bandwidthServer) { s.receiptReply = `{"success":false}` },
			wantErr:  []string{"without success", "receipt sent=true"},
			wantGets: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := defaultBandwidthServer()
			tt.mutate(s)
			ts := httptest.NewTLSServer(s.handler(t))
			defer ts.Close()
			defer setMethod("GET")()

			resp, err := newUTLSTestClient(ts).Fetch(ts.URL+"/", "", nil)
			if err == nil {
				resp.Body.Close()
				t.Fatal("expected an error, got nil")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			// None of these may fall through to re-GETting the target
			// without clearance.
			if s.gets != tt.wantGets {
				t.Errorf("GET / issued %d times, want %d", s.gets, tt.wantGets)
			}
		})
	}
}
