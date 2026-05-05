package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type CertificateGenerator struct {
	PrivateKey  ed25519.PrivateKey
	Certificate *x509.Certificate
}

// конструктор. инициализируем Приватный ключ и корневой сертификат (если есть читаем из файла)
// TODO : здесь стоит разделить логику
func NewCertificateGenerator(certPath, keyPath, orgName string) (*CertificateGenerator, error) {
	cg := &CertificateGenerator{}

	// читаем из файла
	if _, err := os.Stat(certPath); err == nil {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		certBlock, _ := pem.Decode(certData)
		if certBlock == nil {
			return nil, fmt.Errorf("не удалось декодировать PEM сертификата")
		}
		cg.Certificate, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}

		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		keyBlock, _ := pem.Decode(keyData)
		if keyBlock == nil {
			return nil, fmt.Errorf("не удалось декодировать PEM ключа")
		}
		parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}

		privateKey, ok := parsedKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519")
		}

		cg.PrivateKey = privateKey
		return cg, nil
	}
	// не нашли файл, создаём ключ и сертификат
	publickey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{orgName}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, publickey, privateKey)
	if err != nil {
		return nil, err
	}

	cg.Certificate, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	cg.PrivateKey = privateKey

	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cg.Certificate.Raw})
	certFile.Close()

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(cg.PrivateKey)
	if err != nil {
		return nil, err
	}
	pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyFile.Close()

	return cg, nil
}

// IssueCameraCertificate выпускает уникальный сертификат и аппаратный ключ для конкретной камеры.
func (cg *CertificateGenerator) IssueCameraCertificate(cameraID string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Генерируем уникальный аппаратный (долговременный) ключ для этой камеры
	camPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка генерации ключа камеры: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// шаблон сертификата-паспорта для камеры
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: cg.Certificate.Subject.Organization,
			CommonName:   cameraID,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, cg.Certificate, &camPrivKey.PublicKey, cg.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка подписи сертификата камеры: %w", err)
	}

	camCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return camCert, camPrivKey, nil
}
