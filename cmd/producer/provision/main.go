package main

import (
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/tpm"
	"errors"
	"log"
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

	if err := authcrypto.SaveRSAPublicKey(publicKey, cameraPublicKeyPem); err != nil {
		log.Fatalf("%v: save camera public key: %v", ErrGeneratePublicKey, err)
	}

	log.Printf("camera public key exported successfully: %s", cameraPublicKeyPem)
}
