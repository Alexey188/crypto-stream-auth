package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrGenerateRootCA         = errors.New("generate root ca certificate")
	ErrLoadFactory            = errors.New("load root ca certificate")
	ErrIssueCameraCertificate = errors.New("issue camera certificate")
	ErrSaveRootCA             = errors.New("save root ca")
	ErrSaveCertificate        = errors.New("save certificate")
	ErrSavePublicKey          = errors.New("save public key")
	ErrInvalidCertificate     = errors.New("invalid certificate")
)

const (
	rootCAKeyBits = 4096
	cameraKeyBits = 2048

	cameraIdentityScheme = "trustcam"
	cameraIdentityPrefix = "camera:"
)

type RootCA struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

type FactoryAuthority struct {
	rootCA *RootCA
}

func NewFactoryAuthority(rootCA *RootCA) (*FactoryAuthority, error) {
	if err := validateRootCA(rootCA); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadFactory, err)
	}

	return &FactoryAuthority{rootCA: rootCA}, nil
}

func LoadFactoryAuthority(certPath, keyPath string) (*FactoryAuthority, error) {
	rootCA, err := LoadFactoryRootCA(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &FactoryAuthority{rootCA: rootCA}, nil
}

func (factory *FactoryAuthority) IssueCameraCertificate(cameraID string, cameraPublicKey *rsa.PublicKey) (*x509.Certificate, error) {
	if factory == nil {
		return nil, fmt.Errorf("%w: factory authority is nil", ErrIssueCameraCertificate)
	}

	return IssueCameraCertificate(factory.rootCA, cameraID, cameraPublicKey)
}

func GenerateRootCA(orgName string) (*RootCA, error) {
	rootCA := &RootCA{}

	privateKey, err := rsa.GenerateKey(rand.Reader, rootCAKeyBits)
	if err != nil {
		return nil, fmt.Errorf("%w: error generate private key: %w", ErrGenerateRootCA, err)
	}

	if err := validateRootCAPrivateKey(privateKey); err != nil {
		return nil, fmt.Errorf("%w: invalid RootCA private key: %w", ErrGenerateRootCA, err)
	}

	publicKey := &privateKey.PublicKey

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("%w: error generate serial number: %w", ErrGenerateRootCA, err)
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{orgName}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: error create certificate: %w", ErrGenerateRootCA, err)

	}

	rootCA.Certificate, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse certificate: %w", ErrGenerateRootCA, err)
	}
	rootCA.PrivateKey = privateKey

	return rootCA, nil
}

func LoadFactoryRootCA(certPath, keyPath string) (*RootCA, error) {
	cert, err := LoadCertificate(certPath)
	if err != nil {
		return nil, fmt.Errorf("%w: load certificate: %w", ErrLoadFactory, err)
	}

	key, err := LoadRSAPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: load private key: %w", ErrLoadFactory, err)
	}

	rootCA := &RootCA{
		Certificate: cert,
		PrivateKey:  key,
	}
	if err := validateRootCA(rootCA); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadFactory, err)
	}

	return rootCA, nil
}

func LoadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rsa private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode PEM private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return rsaKey, nil
}

func SaveRootCA(rootCA *RootCA, certPath, keyPath string) error {
	if err := validateRootCA(rootCA); err != nil {
		return fmt.Errorf("%w: invalid RootCA: %w", ErrSaveRootCA, err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(rootCA.PrivateKey)
	if err != nil {
		return fmt.Errorf("%w: marshal private key: %w", ErrSaveRootCA, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Certificate.Raw})
	if certPEM == nil {
		return fmt.Errorf("%w: encode certificate", ErrSaveRootCA)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if keyPEM == nil {
		return fmt.Errorf("%w: encode private key", ErrSaveRootCA)
	}

	if err := writeFilesOnce([]fileToWrite{
		{path: certPath, data: certPEM, perm: 0644},
		{path: keyPath, data: keyPEM, perm: 0600},
	}); err != nil {
		return fmt.Errorf("%w: write root ca files: %w", ErrSaveRootCA, err)
	}

	return nil
}

func IssueCameraCertificate(rootCA *RootCA, cameraID string, cameraPublicKey *rsa.PublicKey) (*x509.Certificate, error) {
	if err := validateCameraID(cameraID); err != nil {
		return nil, fmt.Errorf("%w: invalid camera id: %w", ErrIssueCameraCertificate, err)
	}
	if err := validateRootCA(rootCA); err != nil {
		return nil, fmt.Errorf("%w: invalid RootCA: %w", ErrIssueCameraCertificate, err)
	}

	if err := validateCameraPublicKey(cameraPublicKey); err != nil {
		return nil, fmt.Errorf("%w: invalid Camera public key: %w", ErrIssueCameraCertificate, err)
	}

	cameraUID, err := CameraUIDFromPublicKey(cameraPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: calculate camera uid: %w", ErrIssueCameraCertificate, err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("%w: generate serial number: %w", ErrIssueCameraCertificate, err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cameraID,
		},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(365 * 24 * time.Hour),
		URIs:      []*url.URL{cameraIdentityURI(cameraUID)},

		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.SHA384WithRSAPSS,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		template,
		rootCA.Certificate,
		cameraPublicKey,
		rootCA.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: create certificate: %w", ErrIssueCameraCertificate, err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse certificate: %w", ErrIssueCameraCertificate, err)
	}

	return cert, nil
}

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

	if cameraCertificate.SignatureAlgorithm != x509.SHA384WithRSAPSS {
		return nil, fmt.Errorf(
			"%w: camera certificate signature algorithm is %s, want %s",
			ErrInvalidCertificate,
			cameraCertificate.SignatureAlgorithm,
			x509.SHA384WithRSAPSS,
		)
	}

	cameraUID, err := ExtractCameraUID(cameraCertificate)
	if err != nil {
		return nil, fmt.Errorf("%w: extract camera uid: %w", ErrInvalidCertificate, err)
	}

	expectedCameraUID, err := CameraUIDFromPublicKey(cameraPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: calculate camera uid: %w", ErrInvalidCertificate, err)
	}
	if cameraUID != expectedCameraUID {
		return nil, fmt.Errorf("%w: camera uid mismatch", ErrInvalidCertificate)
	}

	return cameraPublicKey, nil
}

func ExtractCameraUID(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("%w: certificate is nil", ErrInvalidCertificate)
	}

	for _, uri := range cert.URIs {
		if uri == nil || uri.Scheme != cameraIdentityScheme {
			continue
		}
		if !strings.HasPrefix(uri.Opaque, cameraIdentityPrefix) {
			continue
		}

		cameraUID := strings.TrimPrefix(uri.Opaque, cameraIdentityPrefix)
		if err := validateCameraUID(cameraUID); err != nil {
			return "", fmt.Errorf("%w: invalid camera uid in certificate: %w", ErrInvalidCertificate, err)
		}
		return cameraUID, nil
	}

	return "", fmt.Errorf("%w: camera uid SAN URI is missing", ErrInvalidCertificate)
}

func CameraUIDFromPublicKey(publicKey *rsa.PublicKey) (string, error) {
	if err := validateCameraPublicKey(publicKey); err != nil {
		return "", err
	}

	data, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal camera public key: %w", err)
	}

	return SHA256Hex(data), nil
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func cameraIdentityURI(cameraUID string) *url.URL {
	return &url.URL{
		Scheme: cameraIdentityScheme,
		Opaque: cameraIdentityPrefix + cameraUID,
	}
}

func validateRootCA(rootCA *RootCA) error {
	if rootCA == nil {
		return fmt.Errorf("RootCA is nil")
	}
	if rootCA.Certificate == nil {
		return fmt.Errorf("RootCA certificate is nil")
	}
	if err := validateRootCAPrivateKey(rootCA.PrivateKey); err != nil {
		return fmt.Errorf("invalid RootCA private key: %w", err)
	}
	if err := validateRootCACertificate(rootCA.Certificate); err != nil {
		return fmt.Errorf("invalid RootCA certificate: %w", err)
	}
	if err := validateRootCAKeyPair(rootCA.Certificate, rootCA.PrivateKey); err != nil {
		return err
	}

	return nil
}

func validateRootCACertificate(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}
	if !cert.IsCA {
		return fmt.Errorf("certificate must be CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate missing cert sign key usage")
	}
	if cert.SignatureAlgorithm != x509.SHA384WithRSAPSS {
		return fmt.Errorf("certificate signature algorithm is %s, want %s", cert.SignatureAlgorithm, x509.SHA384WithRSAPSS)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("certificate self signature is invalid: %w", err)
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not RSA")
	}
	if publicKey.N == nil {
		return fmt.Errorf("certificate public key modulus is nil")
	}
	if publicKey.N.BitLen() != rootCAKeyBits {
		return fmt.Errorf("certificate public key size is %d bits, want %d", publicKey.N.BitLen(), rootCAKeyBits)
	}

	return nil
}

func validateRootCAKeyPair(cert *x509.Certificate, key *rsa.PrivateKey) error {
	certPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("RootCA certificate public key is not RSA")
	}
	if certPublicKey.N.Cmp(key.PublicKey.N) != 0 || certPublicKey.E != key.PublicKey.E {
		return fmt.Errorf("RootCA certificate and private key do not match")
	}

	return nil
}

func validateRootCAPrivateKey(key *rsa.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("private key is nil")
	}
	if key.N == nil {
		return fmt.Errorf("private key modulus is nil")
	}
	if key.N.BitLen() != rootCAKeyBits {
		return fmt.Errorf("private key size is %d bits, want %d", key.N.BitLen(), rootCAKeyBits)
	}
	return nil
}

func validateCameraPublicKey(key *rsa.PublicKey) error {
	if key == nil {
		return fmt.Errorf("public key is nil")
	}
	if key.N == nil {
		return fmt.Errorf("public key modulus is nil")
	}
	if key.N.BitLen() != cameraKeyBits {
		return fmt.Errorf("public key size is %d bits, want %d", key.N.BitLen(), cameraKeyBits)
	}
	return nil
}

func validateCameraID(cameraID string) error {
	if cameraID == "" {
		return fmt.Errorf("camera id is empty")
	}
	if strings.TrimSpace(cameraID) != cameraID {
		return fmt.Errorf("camera id has surrounding spaces")
	}
	if strings.Contains(cameraID, ":") {
		return fmt.Errorf("camera id must not contain ':'")
	}

	return nil
}

func validateCameraUID(cameraUID string) error {
	if !isSHA256Hex(cameraUID) {
		return fmt.Errorf("camera uid must be sha256 hex")
	}

	return nil
}

func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode camera public key")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}

		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("camera public key is not rsa")
		}

		return rsaKey, nil
	case "RSA PUBLIC KEY":
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse rsa public key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported camera public key type %q", block.Type)
	}
}

func SaveRSAPublicKey(publicKey *rsa.PublicKey, path string) error {
	if err := validateCameraPublicKey(publicKey); err != nil {
		return fmt.Errorf("%w: invalid rsa public key: %w", ErrSavePublicKey, err)
	}

	data, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("%w: marshal rsa public key: %w", ErrSavePublicKey, err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data})
	if publicKeyPEM == nil {
		return fmt.Errorf("%w: encode rsa public key", ErrSavePublicKey)
	}

	if err := writeFileOnce(path, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("%w: write rsa public key: %w", ErrSavePublicKey, err)
	}

	return nil
}

func SaveCertificate(cert *x509.Certificate, path string) error {
	if cert == nil {
		return fmt.Errorf("%w: certificate is nil", ErrSaveCertificate)
	}

	if err := writeFileOnce(
		path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		0644,
	); err != nil {
		return fmt.Errorf("%w: write certificate: %w", ErrSaveCertificate, err)
	}

	return nil
}

func writeFileOnce(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create file once: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

type fileToWrite struct {
	path string
	data []byte
	perm os.FileMode
}

func writeFilesOnce(files []fileToWrite) (err error) {
	opened := make([]*os.File, 0, len(files))
	createdPaths := make([]string, 0, len(files))

	defer func() {
		for _, file := range opened {
			if file != nil {
				_ = file.Close()
			}
		}
		if err != nil {
			for _, path := range createdPaths {
				_ = os.Remove(path)
			}
		}
	}()

	for _, file := range files {
		if err := os.MkdirAll(filepath.Dir(file.path), 0755); err != nil {
			return fmt.Errorf("create parent directory: %w", err)
		}

		openedFile, err := os.OpenFile(file.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.perm)
		if err != nil {
			return fmt.Errorf("create file once %s: %w", file.path, err)
		}

		opened = append(opened, openedFile)
		createdPaths = append(createdPaths, file.path)
	}

	for i, file := range files {
		if _, err := opened[i].Write(file.data); err != nil {
			return fmt.Errorf("write file %s: %w", file.path, err)
		}
		if err := opened[i].Close(); err != nil {
			return fmt.Errorf("close file %s: %w", file.path, err)
		}
		opened[i] = nil
	}

	return nil
}
