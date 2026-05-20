package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
)

func TestCameraCertificate(t *testing.T) {
	t.Run("issues_and_verifies_camera_certificate", func(t *testing.T) {
		rootCA, err := GenerateRootCA("Test Root")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		cameraPrivateKey, err := rsa.GenerateKey(rand.Reader, cameraKeyBits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		cameraCertificate, err := IssueCameraCertificate(rootCA, "cam-test", &cameraPrivateKey.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate() error = %v", err)
		}

		if cameraCertificate.SignatureAlgorithm != x509.SHA384WithRSAPSS {
			t.Fatalf("signature algorithm = %s, want %s", cameraCertificate.SignatureAlgorithm, x509.SHA384WithRSAPSS)
		}

		cameraPublicKey, err := VerifyCameraCertificate(cameraCertificate, rootCA.Certificate)
		if err != nil {
			t.Fatalf("VerifyCameraCertificate() error = %v", err)
		}
		if cameraPublicKey.N.Cmp(cameraPrivateKey.PublicKey.N) != 0 {
			t.Fatalf("camera public key mismatch")
		}
	})

	t.Run("rejects_wrong_rsa_key_size", func(t *testing.T) {
		rootCA, err := GenerateRootCA("Test Root")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		wrongKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		_, err = IssueCameraCertificate(rootCA, "cam-test", &wrongKey.PublicKey)
		if !errors.Is(err, ErrIssueCameraCertificate) {
			t.Fatalf("IssueCameraCertificate() error = %v, want %v", err, ErrIssueCameraCertificate)
		}
	})
}
