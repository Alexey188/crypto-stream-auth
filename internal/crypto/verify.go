package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

var ErrInvalidCertificate = errors.New("invalid certificate")

// проверка сертификата камеры и публичного ключа
func VerifyCameraCertificate(cameraCertificate *x509.Certificate, rootCA *x509.Certificate) (*rsa.PublicKey, error) {
	if cameraCertificate == nil {
		return nil, fmt.Errorf("%w: camera certificate is nil", ErrInvalidCertificate)
	}

	if rootCA == nil {
		return nil, fmt.Errorf("%w: root ca is nil", ErrInvalidCertificate)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCA)

	if _, err := cameraCertificate.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		return nil, fmt.Errorf("%w: verify chain: %w", ErrInvalidCertificate, err)
	}

	cameraPublicKey, ok := cameraCertificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: camera public key is not RSA", ErrInvalidCertificate)
	}

	if err := validateCameraPublicKey(cameraPublicKey); err != nil {
		return nil, fmt.Errorf("%w: invalid camera public key: %w", ErrInvalidCertificate, err)
	}

	if cameraCertificate.IsCA {
		return nil, fmt.Errorf("%w: camera certificate must not be CA", ErrInvalidCertificate)
	}

	if cameraCertificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("%w: missing digital signature key usage", ErrInvalidCertificate)
	}

	return cameraPublicKey, nil
}
