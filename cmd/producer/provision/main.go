package main

import (
	"crypto-stream-auth/internal/fileutil"
	"crypto-stream-auth/internal/tpm"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// TODO: если KeyHandle у tpm уже занят, нужно выбрать свободный идентификатор
const (
	cameraKeyHandle    uint32 = 0x81000001
	cameraPublicKeyPem        = "artifacts/keys/camera_public.pem"
)

var (
	ErrGeneratePublicKey = errors.New("public key from tpm")
)

func main() {
	signer, err := tpm.OpenSigner(cameraKeyHandle, nil)
	if err != nil {
		if !tpm.IsPersistentHandleNotFound(err) {
			log.Fatalf("open existing tpm camera key: %v", err)
		}

		signer, err = tpm.ProvisionSigner(cameraKeyHandle, nil, nil)
		if err != nil {
			log.Fatalf("provision tpm camera key: %v", err)
		}
	}
	defer signer.Close()

	publicKey, err := signer.PublicKey()
	if err != nil {
		log.Fatalf("%v: read tpm camera public key: %v ", ErrGeneratePublicKey, err)
	}

	if err := saveCameraPublicKey(publicKey, cameraPublicKeyPem); err != nil {
		log.Fatalf("%v: save camera public key: %v", ErrGeneratePublicKey, err)
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

	return fileutil.WriteFileOnce(
		path,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}),
		0644,
	)
}
