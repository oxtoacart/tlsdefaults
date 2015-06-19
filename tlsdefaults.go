// Package tlsdefaults provides sensible defaults for using TLS.
package tlsdefaults

import (
	"crypto/tls"
)

var (
	// The ECDHE cipher suites are preferred for performance and forward
	// secrecy.  3des and GCM modes See https://community.qualys.com/blogs/securitylabs/2013/06/25/ssl-labs-deploying-forward-secrecy.
	// and http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r1.pdf.
	preferredCipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
)

// Server provides a tls.Config with sensible defaults for server use.
func Server() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS10, // mitigate against POODLE
		PreferServerCipherSuites: true,
		CipherSuites:             preferredCipherSuites, // maximize likelihood of perfect forward secrecy
	}
}
