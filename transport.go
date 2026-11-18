package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// utlsTransport is an http.RoundTripper that dials TLS with utls
// (for browser-like fingerprints) and dispatches to HTTP/2 or HTTP/1.1
// based on the ALPN-negotiated protocol.
type utlsTransport struct {
	dialTLS func(ctx context.Context, network, addr string) (net.Conn, error)

	mu      sync.Mutex
	h2Conns map[string]*http2.ClientConn
}

func (t *utlsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	hostPort := net.JoinHostPort(addr, port)

	// An HTTP/1.1 Upgrade (the Tartarus bandwidth WebSocket) takes over its
	// connection, so it never rides a cached h2 conn and always dials fresh.
	upgrade := req.Header.Get("Upgrade") != ""

	// Try reusing a cached HTTP/2 connection.
	var cc *http2.ClientConn
	if !upgrade {
		t.mu.Lock()
		cc = t.h2Conns[hostPort]
		t.mu.Unlock()
	}
	if cc != nil {
		slog.Debug("transport: reusing h2 conn", "method", req.Method, "url", req.URL)
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		slog.Debug("transport: cached h2 conn failed, dialing new", "err", err)
		t.mu.Lock()
		delete(t.h2Conns, hostPort)
		t.mu.Unlock()
	} else {
		slog.Debug("transport: no cached conn, dialing new", "method", req.Method, "url", req.URL)
	}

	conn, err := t.dialTLS(req.Context(), "tcp", hostPort)
	if err != nil {
		return nil, err
	}

	// Check ALPN negotiated protocol.
	alpn := ""
	if uconn, ok := conn.(*utls.UConn); ok {
		alpn = uconn.ConnectionState().NegotiatedProtocol
	}

	if alpn == "h2" && upgrade {
		// WebSockets over HTTP/2 need RFC 8441 extended CONNECT, which this
		// transport doesn't speak. The Tartarus onion negotiates http/1.1
		// today; fail loudly if that changes rather than send a bogus request.
		conn.Close()
		return nil, fmt.Errorf("server negotiated h2 for %s %s; WebSocket over HTTP/2 is not implemented", req.Method, req.URL)
	}

	if alpn == "h2" {
		cc, err := (&http2.Transport{}).NewClientConn(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		t.mu.Lock()
		if t.h2Conns == nil {
			t.h2Conns = make(map[string]*http2.ClientConn)
		}
		t.h2Conns[hostPort] = cc
		t.mu.Unlock()
		return cc.RoundTrip(req)
	}

	// HTTP/1.1 fallback.
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// Hand the connection itself back as the body, as net/http's
		// Transport does: WebSocket clients require an io.ReadWriteCloser.
		// Reads go through br, which may already hold the first frames.
		resp.Body = &upgradedConn{Reader: br, Conn: conn}
	}
	return resp, nil
}

// upgradedConn is the body of a 101 Switching Protocols response: the raw
// connection, read through the buffer that parsed the response headers.
type upgradedConn struct {
	*bufio.Reader
	net.Conn
}

func (u *upgradedConn) Read(p []byte) (int, error) { return u.Reader.Read(p) }

func NewTorClient() *TorClient {
	proxyURL, err := url.Parse(*socksAddr)
	if err != nil {
		log.Fatalf("Failed to parse proxy URL %q: %v\n", *socksAddr, err)
	}
	socksDialer, err := proxy.FromURL(proxyURL, proxy.Direct)
	if err != nil {
		log.Fatalf("Failed to create SOCKS dialer: %v\n", err)
	}

	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		// TCP dial through the SOCKS5 proxy.
		rawConn, err := socksDialer.(proxy.ContextDialer).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// TLS handshake with Tor Browser's fingerprint.
		// Skip verification: onion services authenticate via the .onion
		// address itself, so the server cert is cosmetic and often expired.
		cfg := &utls.Config{ServerName: host, InsecureSkipVerify: true}
		uConn := utls.UClient(rawConn, cfg, utls.HelloCustom)
		if err := uConn.ApplyPreset(torBrowserClientHello()); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("applying Tor Browser ClientHello: %w", err)
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return uConn, nil
	}

	jar, _ := cookiejar.New(nil)
	httpClient := http.Client{
		Transport: &utlsTransport{dialTLS: dialTLS},
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects automatically; Fetch() handles them.
			return http.ErrUseLastResponse
		},
	}
	return &TorClient{c: httpClient}
}
