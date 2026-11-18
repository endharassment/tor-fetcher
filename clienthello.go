package main

import (
	utls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/dicttls"
)

// torBrowserClientHello returns the TLS ClientHello Tor Browser 15.0.19 sends.
//
// utls's stock Firefox presets do NOT work here. The newest is
// HelloFirefox_120 (what HelloFirefox_Auto resolves to), and no Tor Browser was
// ever built on Firefox 120 -- TB 14 is Firefox 128 ESR, TB 15 is 140 ESR. Two
// concrete consequences: the 120 preset offers
// TLS_ECDHE_ECDSA_WITH_AES_{128,256}_CBC_SHA, which Tor Browser disables
// outright (security.ssl3.ecdhe_ecdsa_aes_{128,256}_sha in 001-base-profile.js),
// and it lacks the X25519MLKEM768 post-quantum key share that Firefox has sent
// since 132. Offering suites no Tor Browser offers is a positive tell, not just
// a gap.
//
// This spec was captured, not guessed: Firefox 140.13.0esr (the build Tor
// Browser 15.0.19 ships) was run against a local listener with Tor Browser's
// TLS prefs applied, and the raw ClientHello was decoded with utls's
// Fingerprinter. TestTorBrowserClientHello pins the properties that matter.
func torBrowserClientHello() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// No ECDHE_ECDSA CBC_SHA suites here: Tor Browser disables them.
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				utls.CurveID(256), // ffdhe2048
				utls.CurveID(257), // ffdhe3072
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.FakeDelegatedCredentialsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					utls.ECDSAWithSHA1,
				},
			},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
				{Group: utls.CurveP256},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.ECDSAWithP256AndSHA256,
					utls.ECDSAWithP384AndSHA384,
					utls.ECDSAWithP521AndSHA512,
					utls.PSSWithSHA256,
					utls.PSSWithSHA384,
					utls.PSSWithSHA512,
					utls.PKCS1WithSHA256,
					utls.PKCS1WithSHA384,
					utls.PKCS1WithSHA512,
					utls.ECDSAWithSHA1,
					utls.PKCS1WithSHA1,
				},
			},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
				utls.CertCompressionBrotli,
				utls.CertCompressionZstd,
			}},
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
				},
				CandidatePayloadLens: []uint16{223},
			},
		},
	}
}
