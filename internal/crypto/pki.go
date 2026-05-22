package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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
)

type RootCA struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

// конструктор. инициализируем Приватный ключ и корневой сертификат.
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

	if err := validateRootCAPrivateKey(key); err != nil {
		return nil, fmt.Errorf("%w: invalid private key: %w", ErrLoadFactory, err)
	}

	return &RootCA{
		Certificate: cert,
		PrivateKey:  key,
	}, nil
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

	if rootCA == nil {
		return fmt.Errorf("%w: certificate generator is nil", ErrSaveRootCA)
	}

	if rootCA.Certificate == nil {
		return fmt.Errorf("%w: certificate is nil", ErrSaveRootCA)
	}

	if err := validateRootCAPrivateKey(rootCA.PrivateKey); err != nil {
		return fmt.Errorf("%w: invalid RootCA private key: %w", ErrSaveRootCA, err)
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

	if err := writeFileOnce(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("%w: write root ca certificate: %w", ErrSaveRootCA, err)
	}

	if err := writeFileOnce(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("%w: write root ca private key: %w", ErrSaveRootCA, err)
	}

	return nil
}

// логика выпуска сертификатов для камеры
// cameraPublicKey - из tpm модуля
func IssueCameraCertificate(rootCA *RootCA, cameraID string, cameraPublicKey *rsa.PublicKey) (*x509.Certificate, error) {
	if rootCA == nil {
		return nil, fmt.Errorf("%w: RootCa is nil", ErrIssueCameraCertificate)
	}

	if rootCA.Certificate == nil {
		return nil, fmt.Errorf("%w: RootCa certificate is nil", ErrIssueCameraCertificate)
	}

	if cameraID == "" {
		return nil, fmt.Errorf("%w: CameraID invalid value", ErrIssueCameraCertificate)

	}
	if err := validateRootCAPrivateKey(rootCA.PrivateKey); err != nil {
		return nil, fmt.Errorf("%w: invalid RootCA private key: %w", ErrIssueCameraCertificate, err)
	}

	if err := validateCameraPublicKey(cameraPublicKey); err != nil {
		return nil, fmt.Errorf("%w: invalid Camera public key: %w", ErrIssueCameraCertificate, err)
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

	return cameraPublicKey, nil
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

// Загрузка публичного ключа камеры (которая из tpm)
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

// сохранение сертификата камеры
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
