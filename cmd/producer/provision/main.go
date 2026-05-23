package main

import (
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/tpm"
	"errors"
	"log"
)

const (
	cameraPublicKeyPem = "artifacts/camera/camera_public2.pem"
)

var (
	ErrGeneratePublicKey = errors.New("public key from tpm")
)

func main() {
	handle := tpm.DefaultCameraKeyHandle

	signer, err := tpm.OpenSigner(handle, nil)
	if err != nil {
		if !tpm.IsPersistentHandleNotFound(err) {
			log.Fatalf("open existing tpm camera key 0x%x: %v", handle, err)
		}

		log.Printf("tpm camera key not found: handle=0x%x", handle)

		signer, err = tpm.ProvisionSigner(handle, nil, nil)
		if err != nil {
			log.Fatalf("provision tpm camera key 0x%x: %v", handle, err)
		}
		log.Printf("created new tpm camera key: handle=0x%x", handle)
	} else {
		log.Printf("opened existing tpm camera key: handle=0x%x", handle)
	}
	defer signer.Close()

	publicKey, err := signer.PublicKey()
	if err != nil {
		log.Fatalf("%v: read tpm camera public key: %v ", ErrGeneratePublicKey, err)
	}

	if err := authcrypto.SaveRSAPublicKey(publicKey, cameraPublicKeyPem); err != nil {
		log.Fatalf("%v: save camera public key: %v", ErrGeneratePublicKey, err)
	}

	log.Printf("camera public key exported successfully: handle=0x%x path=%s", handle, cameraPublicKeyPem)
}
