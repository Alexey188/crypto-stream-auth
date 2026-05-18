package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	authcrypto "crypto-stream-auth/internal/crypto"
)

const (
	rootCertPath        = "certs/root_ca.crt"
	rootKeyPath         = "certs/root_ca.key"
	cameraID            = "cam-001"
	cameraPublicKeyPath = "certs/camera_public.pem"
	cameraCertPath      = "certs/camera.crt"
)

func main() {
	rootCA, err := authcrypto.LoadRootCA(rootCertPath, rootKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	cameraPublicKey, err := loadCameraPublicKey(cameraPublicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	cameraCert, err := authcrypto.IssueCameraCertificate(rootCA, cameraID, cameraPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	if err := saveCameraCertificate(cameraCert, cameraCertPath); err != nil {
		log.Fatal(err)
	}
}

func loadCameraPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode camera public key")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("camera public key is not rsa")
		}

		return rsaKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported camera public key type %q", block.Type)
	}
}

func saveCameraCertificate(cert *x509.Certificate, path string) error {
	return os.WriteFile(
		path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		0644,
	)
}
