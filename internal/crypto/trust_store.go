package crypto

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var ErrTrustStore = errors.New("trust store")

const (
	trustedRootsDirName   = "roots"
	cameraManifestName    = "camera_manifest.json"
	rootCertificateExtCRT = ".crt"
	rootCertificateExtPEM = ".pem"
)

type CameraManifest struct {
	Cameras []CameraManifestEntry `json:"cameras"`
}

type CameraManifestEntry struct {
	CameraUID               string `json:"camera_uid"`
	CameraID                string `json:"camera_id"`
	CameraCertificateSHA256 string `json:"camera_cert_sha256"`
	RootCASHA256            string `json:"root_ca_sha256"`
}

type TrustStore struct {
	rootsByFingerprint map[string]*x509.Certificate
	camerasByUID       map[string]CameraManifestEntry
}

func (factory *FactoryAuthority) NewCameraManifest(cameraCertificate *x509.Certificate) (*CameraManifest, error) {
	if factory == nil {
		return nil, fmt.Errorf("%w: factory authority is nil", ErrTrustStore)
	}

	return NewCameraManifest(factory.rootCA.Certificate, cameraCertificate)
}

func NewCameraManifest(rootCA *x509.Certificate, cameraCertificate *x509.Certificate) (*CameraManifest, error) {
	entry, err := newCameraManifestEntry(rootCA, cameraCertificate)
	if err != nil {
		return nil, err
	}

	return &CameraManifest{Cameras: []CameraManifestEntry{entry}}, nil
}

func SaveCameraManifest(manifest *CameraManifest, path string) error {
	if err := validateCameraManifest(manifest); err != nil {
		return fmt.Errorf("%w: invalid camera manifest: %w", ErrTrustStore, err)
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: marshal camera manifest: %w", ErrTrustStore, err)
	}
	data = append(data, '\n')

	if err := writeFileOnce(path, data, 0644); err != nil {
		return fmt.Errorf("%w: write camera manifest: %w", ErrTrustStore, err)
	}

	return nil
}

func SaveCameraCertificateBundle(cameraCertificate *x509.Certificate, manifest *CameraManifest, certPath string, manifestPath string) error {
	if cameraCertificate == nil {
		return fmt.Errorf("%w: camera certificate is nil", ErrSaveCertificate)
	}
	if err := validateCameraManifest(manifest); err != nil {
		return fmt.Errorf("%w: invalid camera manifest: %w", ErrSaveCertificate, err)
	}

	mergedManifest, err := mergeCameraManifestFile(manifestPath, manifest)
	if err != nil {
		return fmt.Errorf("%w: merge camera manifest: %w", ErrSaveCertificate, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cameraCertificate.Raw})
	if certPEM == nil {
		return fmt.Errorf("%w: encode camera certificate", ErrSaveCertificate)
	}

	manifestJSON, err := json.MarshalIndent(mergedManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: marshal camera manifest: %w", ErrSaveCertificate, err)
	}
	manifestJSON = append(manifestJSON, '\n')

	if err := writeFileOnce(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("%w: write camera certificate: %w", ErrSaveCertificate, err)
	}

	if err := writeFileReplace(manifestPath, manifestJSON, 0644); err != nil {
		return fmt.Errorf("%w: write camera manifest: %w", ErrSaveCertificate, err)
	}

	return nil
}

func mergeCameraManifestFile(path string, newManifest *CameraManifest) (*CameraManifest, error) {
	merged := &CameraManifest{}

	existing, err := LoadCameraManifest(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if existing != nil {
		merged.Cameras = append(merged.Cameras, existing.Cameras...)
	}

	indexByUID := make(map[string]int, len(merged.Cameras))
	for i, camera := range merged.Cameras {
		indexByUID[camera.CameraUID] = i
	}

	for _, camera := range newManifest.Cameras {
		if existingIndex, ok := indexByUID[camera.CameraUID]; ok {
			merged.Cameras[existingIndex] = camera
			continue
		}

		indexByUID[camera.CameraUID] = len(merged.Cameras)
		merged.Cameras = append(merged.Cameras, camera)
	}

	if err := validateCameraManifest(merged); err != nil {
		return nil, err
	}

	return merged, nil
}

func LoadTrustStore(trustDir string) (*TrustStore, error) {
	if trustDir == "" {
		return nil, fmt.Errorf("%w: trust dir is empty", ErrTrustStore)
	}

	rootCAPaths, err := loadRootCAPaths(filepath.Join(trustDir, trustedRootsDirName))
	if err != nil {
		return nil, err
	}

	return LoadTrustStoreFromFiles(rootCAPaths, filepath.Join(trustDir, cameraManifestName))
}

func LoadTrustStoreFromFiles(rootCAPaths []string, manifestPath string) (*TrustStore, error) {
	if len(rootCAPaths) == 0 {
		return nil, fmt.Errorf("%w: root ca paths are empty", ErrTrustStore)
	}

	rootCAs := make([]*x509.Certificate, 0, len(rootCAPaths))
	for _, path := range rootCAPaths {
		rootCA, err := LoadCertificate(path)
		if err != nil {
			return nil, fmt.Errorf("%w: load root ca certificate %s: %w", ErrTrustStore, path, err)
		}
		rootCAs = append(rootCAs, rootCA)
	}

	manifest, err := LoadCameraManifest(manifestPath)
	if err != nil {
		return nil, err
	}

	return NewTrustStore(rootCAs, manifest)
}

func loadRootCAPaths(rootsDir string) ([]string, error) {
	entries, err := os.ReadDir(rootsDir)
	if err != nil {
		return nil, fmt.Errorf("%w: read trusted roots dir: %w", ErrTrustStore, err)
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != rootCertificateExtCRT && ext != rootCertificateExtPEM {
			continue
		}

		paths = append(paths, filepath.Join(rootsDir, entry.Name()))
	}
	sort.Strings(paths)

	if len(paths) == 0 {
		return nil, fmt.Errorf("%w: no trusted root certificates in %s", ErrTrustStore, rootsDir)
	}

	return paths, nil
}

func LoadCameraManifest(path string) (*CameraManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read camera manifest: %w", ErrTrustStore, err)
	}

	var manifest CameraManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("%w: parse camera manifest: %w", ErrTrustStore, err)
	}
	if err := validateCameraManifest(&manifest); err != nil {
		return nil, fmt.Errorf("%w: invalid camera manifest: %w", ErrTrustStore, err)
	}

	return &manifest, nil
}

func NewTrustStore(rootCAs []*x509.Certificate, manifest *CameraManifest) (*TrustStore, error) {
	if len(rootCAs) == 0 {
		return nil, fmt.Errorf("%w: root ca list is empty", ErrTrustStore)
	}
	if err := validateCameraManifest(manifest); err != nil {
		return nil, fmt.Errorf("%w: invalid camera manifest: %w", ErrTrustStore, err)
	}

	store := &TrustStore{
		rootsByFingerprint: make(map[string]*x509.Certificate, len(rootCAs)),
		camerasByUID:       make(map[string]CameraManifestEntry, len(manifest.Cameras)),
	}

	for _, rootCA := range rootCAs {
		if err := validateRootCACertificate(rootCA); err != nil {
			return nil, fmt.Errorf("%w: invalid root ca certificate: %w", ErrTrustStore, err)
		}

		fingerprint, err := certificateSHA256(rootCA)
		if err != nil {
			return nil, fmt.Errorf("%w: calculate root ca fingerprint: %w", ErrTrustStore, err)
		}
		if _, ok := store.rootsByFingerprint[fingerprint]; ok {
			return nil, fmt.Errorf("%w: duplicate root ca %s", ErrTrustStore, fingerprint)
		}

		store.rootsByFingerprint[fingerprint] = rootCA
	}

	for _, camera := range manifest.Cameras {
		if _, ok := store.rootsByFingerprint[camera.RootCASHA256]; !ok {
			return nil, fmt.Errorf("%w: camera %s expects unknown root ca %s", ErrTrustStore, camera.CameraUID, camera.RootCASHA256)
		}
		store.camerasByUID[camera.CameraUID] = camera
	}

	return store, nil
}

func (store *TrustStore) VerifyCameraCertificate(cameraCertificate *x509.Certificate) (*rsa.PublicKey, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: trust store is nil", ErrTrustStore)
	}

	cameraUID, err := ExtractCameraUID(cameraCertificate)
	if err != nil {
		return nil, fmt.Errorf("%w: extract camera uid: %w", ErrTrustStore, err)
	}

	entry, ok := store.camerasByUID[cameraUID]
	if !ok {
		return nil, fmt.Errorf("%w: camera %s is not registered", ErrTrustStore, cameraUID)
	}

	cameraFingerprint, err := certificateSHA256(cameraCertificate)
	if err != nil {
		return nil, fmt.Errorf("%w: calculate camera certificate fingerprint: %w", ErrTrustStore, err)
	}
	if cameraFingerprint != entry.CameraCertificateSHA256 {
		return nil, fmt.Errorf("%w: camera %s certificate fingerprint mismatch", ErrTrustStore, cameraUID)
	}

	rootCA, ok := store.rootsByFingerprint[entry.RootCASHA256]
	if !ok {
		return nil, fmt.Errorf("%w: camera %s root ca is not loaded", ErrTrustStore, cameraUID)
	}

	return VerifyCameraCertificate(cameraCertificate, rootCA)
}

func newCameraManifestEntry(rootCA *x509.Certificate, cameraCertificate *x509.Certificate) (CameraManifestEntry, error) {
	cameraUID, err := ExtractCameraUID(cameraCertificate)
	if err != nil {
		return CameraManifestEntry{}, fmt.Errorf("%w: extract camera uid: %w", ErrTrustStore, err)
	}

	rootFingerprint, err := certificateSHA256(rootCA)
	if err != nil {
		return CameraManifestEntry{}, fmt.Errorf("%w: calculate root ca fingerprint: %w", ErrTrustStore, err)
	}

	cameraFingerprint, err := certificateSHA256(cameraCertificate)
	if err != nil {
		return CameraManifestEntry{}, fmt.Errorf("%w: calculate camera certificate fingerprint: %w", ErrTrustStore, err)
	}

	return CameraManifestEntry{
		CameraUID:               cameraUID,
		CameraID:                cameraCertificate.Subject.CommonName,
		CameraCertificateSHA256: cameraFingerprint,
		RootCASHA256:            rootFingerprint,
	}, nil
}

func validateCameraManifest(manifest *CameraManifest) error {
	if manifest == nil {
		return fmt.Errorf("manifest is nil")
	}
	if len(manifest.Cameras) == 0 {
		return fmt.Errorf("manifest has no cameras")
	}

	seen := make(map[string]struct{}, len(manifest.Cameras))
	for _, camera := range manifest.Cameras {
		if err := validateCameraUID(camera.CameraUID); err != nil {
			return fmt.Errorf("invalid camera uid %q: %w", camera.CameraUID, err)
		}
		if err := validateCameraID(camera.CameraID); err != nil {
			return fmt.Errorf("invalid camera id %q: %w", camera.CameraID, err)
		}
		if _, ok := seen[camera.CameraUID]; ok {
			return fmt.Errorf("duplicate camera uid %q", camera.CameraUID)
		}
		seen[camera.CameraUID] = struct{}{}

		if !isSHA256Hex(camera.CameraCertificateSHA256) {
			return fmt.Errorf("invalid camera certificate sha256 for %s", camera.CameraID)
		}
		if !isSHA256Hex(camera.RootCASHA256) {
			return fmt.Errorf("invalid root ca sha256 for %s", camera.CameraID)
		}
	}

	return nil
}

func certificateSHA256(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("certificate is nil")
	}

	return SHA256Hex(cert.Raw), nil
}

func isSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}

	_, err := hex.DecodeString(value)
	return err == nil
}

func writeFileReplace(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("remove old file: %w", removeErr)
		}
		if err := os.Rename(tmpPath, path); err != nil {
			return fmt.Errorf("replace file: %w", err)
		}
	}

	return nil
}
