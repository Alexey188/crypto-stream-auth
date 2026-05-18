package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

func NewLocalServerTLSConfig() (*tls.Config, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: generate tls key: %w", ErrTransport, err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("%w: generate tls serial number: %w", ErrTransport, err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: create tls certificate: %w", ErrTransport, err)
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("%w: parse tls certificate: %w", ErrTransport, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certificateDER},
				PrivateKey:  privateKey,
				Leaf:        certificate,
			},
		},
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{ALPN},
	}, nil
}

func NewLocalClientTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
	}
}
