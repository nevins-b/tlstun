package server

import (
	"crypto/sha512"
	"crypto/x509"
)

func certGenerateFingerprint(cert *x509.Certificate) []byte {
	sum := sha512.Sum512(cert.Raw)
	return sum[:]
}

func TrustedResponse() string {
	return "It Works and you have a trusted cert!"
}

func UnTrustedResponse() string {
	return "It Works!"
}
