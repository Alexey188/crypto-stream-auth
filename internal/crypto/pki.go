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
	"time"
)

var (
	ErrGenerateRootCA         = errors.New("generate root ca certificate")
	ErrLoadRootCA             = errors.New("load root ca certificate")
	ErrIssueCameraCertificate = errors.New("issue camera certificate")
	ErrSaveRootCA             = errors.New("save root ca")
	ErrSaveCertificate        = errors.New("save certificate")
)

const (
	rootCAKeyBits = 4096
	cameraKeyBits = 3072
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

func LoadRootCA(certPath, keyPath string) (*RootCA, error) {

	rootCA := &RootCA{}

	if _, err := os.Stat(certPath); err == nil {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		certBlock, _ := pem.Decode(certData)
		if certBlock == nil {
			return nil, fmt.Errorf("%w: error decode PEM certificate", ErrLoadRootCA)
		}
		rootCA.Certificate, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}

		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		keyBlock, _ := pem.Decode(keyData)
		if keyBlock == nil {
			return nil, fmt.Errorf("%w: error decode PEM key", ErrLoadRootCA)
		}
		parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}

		privateKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: private key is not RSA", ErrLoadRootCA)
		}
		if err := validateRootCAPrivateKey(privateKey); err != nil {
			return nil, fmt.Errorf("%w: invalid RootCA private key: %w", ErrLoadRootCA, err)
		}

		rootCA.PrivateKey = privateKey
		return rootCA, nil
	} else {
		return nil, fmt.Errorf("%w: %w", ErrLoadRootCA, err)
	}
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

	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: rootCA.Certificate.Raw}); err != nil {
		_ = certFile.Close()
		return fmt.Errorf("%w: failed to encode certificate: %w", ErrSaveRootCA, err)
	}

	if err := certFile.Close(); err != nil {
		return fmt.Errorf("%w: failed to close certificate file: %w", ErrSaveRootCA, err)

	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(rootCA.PrivateKey)

	if err != nil {
		_ = keyFile.Close()
		return fmt.Errorf("%w: marshal private key: %w", ErrSaveRootCA, err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		_ = keyFile.Close()
		return fmt.Errorf("%w: failed to encode private key: %w", ErrSaveRootCA, err)

	}

	if err := keyFile.Close(); err != nil {
		return fmt.Errorf("%w: failed to close key file: %w", ErrSaveRootCA, err)
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

// сохранение сертификата камеры
func SaveCertificate(cert *x509.Certificate, path string) error {
	if cert == nil {
		return fmt.Errorf("%w: certificate is nil", ErrSaveCertificate)
	}

	if err := os.WriteFile(
		path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		0644,
	); err != nil {
		return fmt.Errorf("%w: write certificate: %w", ErrSaveCertificate, err)
	}

	return nil
}
