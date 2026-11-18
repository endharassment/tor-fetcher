package main

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestTorBrowserClientHello(t *testing.T) {
	spec := torBrowserClientHello()

	// The two suites Tor Browser disables in 001-base-profile.js
	// (security.ssl3.ecdhe_ecdsa_aes_{128,256}_sha). utls's HelloFirefox_120
	// offers both, so using the stock preset would advertise cipher suites no
	// Tor Browser ever advertises -- a positive tell, not just a gap.
	disabled := map[uint16]string{
		0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
	}
	for _, c := range spec.CipherSuites {
		if name, bad := disabled[c]; bad {
			t.Errorf("offering %s (0x%04x), which Tor Browser disables", name, c)
		}
	}

	// Firefox has offered the post-quantum hybrid key share since 132, so a
	// hello without it does not match the version our User-Agent claims.
	var haveCurve, haveKeyShare bool
	var alpn []string
	for _, e := range spec.Extensions {
		switch v := e.(type) {
		case *utls.SupportedCurvesExtension:
			if len(v.Curves) > 0 && v.Curves[0] == utls.X25519MLKEM768 {
				haveCurve = true
			}
		case *utls.KeyShareExtension:
			for _, ks := range v.KeyShares {
				if ks.Group == utls.X25519MLKEM768 {
					haveKeyShare = true
				}
			}
		case *utls.ALPNExtension:
			alpn = v.AlpnProtocols
		}
	}
	if !haveCurve {
		t.Error("X25519MLKEM768 is not the first supported curve")
	}
	if !haveKeyShare {
		t.Error("no X25519MLKEM768 key share offered")
	}
	if len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Errorf("ALPN = %v, want [h2 http/1.1]", alpn)
	}
	// SNI leads the extension list in the capture; ordering is fingerprinted.
	if len(spec.Extensions) == 0 {
		t.Fatal("no extensions")
	}
	if _, ok := spec.Extensions[0].(*utls.SNIExtension); !ok {
		t.Errorf("first extension is %T, want *utls.SNIExtension", spec.Extensions[0])
	}

	// The spec must be usable: ApplyPreset rejects malformed ones.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	uConn := utls.UClient(c1, &utls.Config{ServerName: "example.onion", InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uConn.ApplyPreset(torBrowserClientHello()); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
}
