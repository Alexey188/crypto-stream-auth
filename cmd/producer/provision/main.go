package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"crypto-stream-auth/internal/tpm"
)

// TODO: если KeyHandle у tpm уже занят, нужно выбрать свободный идентификатор
const (
	cameraKeyHandle    uint32 = 0x81000001
	cameraPublicKeyPem        = "certs/camera_public.pem"
)

var (
	ErrGeneratePublicKey = errors.New("public key from tpm")
)

func main() {
	signer, err := tpm.ProvisionSigner(cameraKeyHandle, nil, nil)
	if err != nil {
		log.Fatalf("provision tpm camera key: %v: %v", ErrGeneratePublicKey, err)
	}
	defer signer.Close()

	publicKey, err := signer.PublicKey()
	if err != nil {
		log.Fatalf("read tpm camera public key: %v: %v ", ErrGeneratePublicKey, err)
	}

	if err := saveCameraPublicKey(publicKey, cameraPublicKeyPem); err != nil {
		log.Fatalf("save camera public key: %v :%v", ErrGeneratePublicKey, err)
	}

	log.Printf("camera public key exported successfully: %s", cameraPublicKeyPem)
}

func saveCameraPublicKey(publicKey *rsa.PublicKey, path string) error {
	if publicKey == nil {
		return fmt.Errorf("camera public key is nil")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("%w: %w", ErrGeneratePublicKey, err)
	}

	data, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrGeneratePublicKey, err)

	}

	return os.WriteFile(
		path,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}),
		0644,
	)
}
