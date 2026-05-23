package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"path/filepath"
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

		cameraUID, err := ExtractCameraUID(cameraCertificate)
		if err != nil {
			t.Fatalf("ExtractCameraUID() error = %v", err)
		}
		expectedCameraUID, err := CameraUIDFromPublicKey(&cameraPrivateKey.PublicKey)
		if err != nil {
			t.Fatalf("CameraUIDFromPublicKey() error = %v", err)
		}
		if cameraUID != expectedCameraUID {
			t.Fatalf("camera uid mismatch")
		}

		manifest, err := NewCameraManifest(rootCA.Certificate, cameraCertificate)
		if err != nil {
			t.Fatalf("NewCameraManifest() error = %v", err)
		}
		if manifest.Cameras[0].CameraID != "cam-test" {
			t.Fatalf("camera id = %q, want %q", manifest.Cameras[0].CameraID, "cam-test")
		}
		if manifest.Cameras[0].CameraUID != expectedCameraUID {
			t.Fatalf("manifest camera uid mismatch")
		}

		trustStore, err := NewTrustStore([]*x509.Certificate{rootCA.Certificate}, manifest)
		if err != nil {
			t.Fatalf("NewTrustStore() error = %v", err)
		}

		cameraPublicKey, err = trustStore.VerifyCameraCertificate(cameraCertificate)
		if err != nil {
			t.Fatalf("TrustStore.VerifyCameraCertificate() error = %v", err)
		}
		if cameraPublicKey.N.Cmp(cameraPrivateKey.PublicKey.N) != 0 {
			t.Fatalf("trust store camera public key mismatch")
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

	t.Run("rejects_mismatched_factory_certificate_and_key", func(t *testing.T) {
		rootA, err := GenerateRootCA("Test Root A")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		rootB, err := GenerateRootCA("Test Root B")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		_, err = NewFactoryAuthority(&RootCA{
			Certificate: rootA.Certificate,
			PrivateKey:  rootB.PrivateKey,
		})
		if !errors.Is(err, ErrLoadFactory) {
			t.Fatalf("NewFactoryAuthority() error = %v, want %v", err, ErrLoadFactory)
		}
	})

	t.Run("trust_store_rejects_unexpected_root_ca", func(t *testing.T) {
		rootA, err := GenerateRootCA("Test Root A")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		rootB, err := GenerateRootCA("Test Root B")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		cameraPrivateKey, err := rsa.GenerateKey(rand.Reader, cameraKeyBits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		cameraCertificate, err := IssueCameraCertificate(rootA, "cam-test", &cameraPrivateKey.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate() error = %v", err)
		}

		manifest, err := NewCameraManifest(rootA.Certificate, cameraCertificate)
		if err != nil {
			t.Fatalf("NewCameraManifest() error = %v", err)
		}

		_, err = NewTrustStore([]*x509.Certificate{rootB.Certificate}, manifest)
		if !errors.Is(err, ErrTrustStore) {
			t.Fatalf("NewTrustStore() error = %v, want %v", err, ErrTrustStore)
		}
	})

	t.Run("trust_store_selects_expected_root_ca", func(t *testing.T) {
		rootA, err := GenerateRootCA("Test Root A")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		rootB, err := GenerateRootCA("Test Root B")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		cameraPrivateKey, err := rsa.GenerateKey(rand.Reader, cameraKeyBits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		cameraCertificate, err := IssueCameraCertificate(rootB, "cam-test", &cameraPrivateKey.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate() error = %v", err)
		}

		manifest, err := NewCameraManifest(rootB.Certificate, cameraCertificate)
		if err != nil {
			t.Fatalf("NewCameraManifest() error = %v", err)
		}

		trustStore, err := NewTrustStore([]*x509.Certificate{rootA.Certificate, rootB.Certificate}, manifest)
		if err != nil {
			t.Fatalf("NewTrustStore() error = %v", err)
		}

		if _, err := trustStore.VerifyCameraCertificate(cameraCertificate); err != nil {
			t.Fatalf("TrustStore.VerifyCameraCertificate() error = %v", err)
		}
	})

	t.Run("loads_trust_store_from_directory", func(t *testing.T) {
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

		manifest, err := NewCameraManifest(rootCA.Certificate, cameraCertificate)
		if err != nil {
			t.Fatalf("NewCameraManifest() error = %v", err)
		}

		trustDir := t.TempDir()
		if err := SaveCertificate(rootCA.Certificate, filepath.Join(trustDir, trustedRootsDirName, "root_ca.crt")); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}
		if err := SaveCameraManifest(manifest, filepath.Join(trustDir, cameraManifestName)); err != nil {
			t.Fatalf("SaveCameraManifest() error = %v", err)
		}

		trustStore, err := LoadTrustStore(trustDir)
		if err != nil {
			t.Fatalf("LoadTrustStore() error = %v", err)
		}

		if _, err := trustStore.VerifyCameraCertificate(cameraCertificate); err != nil {
			t.Fatalf("TrustStore.VerifyCameraCertificate() error = %v", err)
		}
	})

	t.Run("camera_certificate_bundle_appends_manifest", func(t *testing.T) {
		rootCA, err := GenerateRootCA("Test Root")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		cameraPrivateKeyA, err := rsa.GenerateKey(rand.Reader, cameraKeyBits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		cameraPrivateKeyB, err := rsa.GenerateKey(rand.Reader, cameraKeyBits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		cameraCertificateA, err := IssueCameraCertificate(rootCA, "cam-a", &cameraPrivateKeyA.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate() error = %v", err)
		}
		cameraCertificateB, err := IssueCameraCertificate(rootCA, "cam-b", &cameraPrivateKeyB.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate() error = %v", err)
		}

		manifestA, err := NewCameraManifest(rootCA.Certificate, cameraCertificateA)
		if err != nil {
			t.Fatalf("NewCameraManifest(A) error = %v", err)
		}
		manifestB, err := NewCameraManifest(rootCA.Certificate, cameraCertificateB)
		if err != nil {
			t.Fatalf("NewCameraManifest(B) error = %v", err)
		}

		dir := t.TempDir()
		if err := SaveCameraCertificateBundle(cameraCertificateA, manifestA, filepath.Join(dir, "camera-a.crt"), filepath.Join(dir, cameraManifestName)); err != nil {
			t.Fatalf("SaveCameraCertificateBundle(A) error = %v", err)
		}
		if err := SaveCameraCertificateBundle(cameraCertificateB, manifestB, filepath.Join(dir, "camera-b.crt"), filepath.Join(dir, cameraManifestName)); err != nil {
			t.Fatalf("SaveCameraCertificateBundle(B) error = %v", err)
		}

		manifest, err := LoadCameraManifest(filepath.Join(dir, cameraManifestName))
		if err != nil {
			t.Fatalf("LoadCameraManifest() error = %v", err)
		}
		if len(manifest.Cameras) != 2 {
			t.Fatalf("manifest cameras = %d, want %d", len(manifest.Cameras), 2)
		}
	})

	t.Run("camera_certificate_bundle_updates_existing_camera_uid", func(t *testing.T) {
		rootCA, err := GenerateRootCA("Test Root")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		cameraPrivateKey, err := rsa.GenerateKey(rand.Reader, cameraKeyBits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		firstCertificate, err := IssueCameraCertificate(rootCA, "cam-001", &cameraPrivateKey.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate(first) error = %v", err)
		}
		secondCertificate, err := IssueCameraCertificate(rootCA, "cam-001", &cameraPrivateKey.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate(second) error = %v", err)
		}

		firstManifest, err := NewCameraManifest(rootCA.Certificate, firstCertificate)
		if err != nil {
			t.Fatalf("NewCameraManifest(first) error = %v", err)
		}
		secondManifest, err := NewCameraManifest(rootCA.Certificate, secondCertificate)
		if err != nil {
			t.Fatalf("NewCameraManifest(second) error = %v", err)
		}

		dir := t.TempDir()
		manifestPath := filepath.Join(dir, cameraManifestName)
		if err := SaveCameraCertificateBundle(firstCertificate, firstManifest, filepath.Join(dir, "first.crt"), manifestPath); err != nil {
			t.Fatalf("SaveCameraCertificateBundle(first) error = %v", err)
		}
		if err := SaveCameraCertificateBundle(secondCertificate, secondManifest, filepath.Join(dir, "second.crt"), manifestPath); err != nil {
			t.Fatalf("SaveCameraCertificateBundle(second) error = %v", err)
		}

		manifest, err := LoadCameraManifest(manifestPath)
		if err != nil {
			t.Fatalf("LoadCameraManifest() error = %v", err)
		}
		if len(manifest.Cameras) != 1 {
			t.Fatalf("manifest cameras = %d, want %d", len(manifest.Cameras), 1)
		}
		if manifest.Cameras[0] != secondManifest.Cameras[0] {
			t.Fatalf("manifest camera was not updated")
		}
	})

	t.Run("trust_store_allows_duplicate_camera_names_with_different_public_keys", func(t *testing.T) {
		rootCA, err := GenerateRootCA("Test Root")
		if err != nil {
			t.Fatalf("GenerateRootCA() error = %v", err)
		}

		cameraPrivateKeyA, err := rsa.GenerateKey(rand.Reader, cameraKeyBits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		cameraPrivateKeyB, err := rsa.GenerateKey(rand.Reader, cameraKeyBits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}

		cameraCertificateA, err := IssueCameraCertificate(rootCA, "cam-001", &cameraPrivateKeyA.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate() error = %v", err)
		}
		cameraCertificateB, err := IssueCameraCertificate(rootCA, "cam-001", &cameraPrivateKeyB.PublicKey)
		if err != nil {
			t.Fatalf("IssueCameraCertificate() error = %v", err)
		}

		manifestA, err := NewCameraManifest(rootCA.Certificate, cameraCertificateA)
		if err != nil {
			t.Fatalf("NewCameraManifest() error = %v", err)
		}
		manifestB, err := NewCameraManifest(rootCA.Certificate, cameraCertificateB)
		if err != nil {
			t.Fatalf("NewCameraManifest() error = %v", err)
		}

		manifest := &CameraManifest{
			Cameras: []CameraManifestEntry{
				manifestA.Cameras[0],
				manifestB.Cameras[0],
			},
		}

		trustStore, err := NewTrustStore([]*x509.Certificate{rootCA.Certificate}, manifest)
		if err != nil {
			t.Fatalf("NewTrustStore() error = %v", err)
		}

		if _, err := trustStore.VerifyCameraCertificate(cameraCertificateA); err != nil {
			t.Fatalf("TrustStore.VerifyCameraCertificate(A) error = %v", err)
		}
		if _, err := trustStore.VerifyCameraCertificate(cameraCertificateB); err != nil {
			t.Fatalf("TrustStore.VerifyCameraCertificate(B) error = %v", err)
		}
	})
}
