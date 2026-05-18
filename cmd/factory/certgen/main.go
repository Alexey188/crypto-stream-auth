package main

import (
	"log"

	authcrypto "crypto-stream-auth/internal/crypto"
)

const (
	rootCertPath        = "artifacts/certs/root_ca.crt"
	rootKeyPath         = "artifacts/keys/root_ca.key"
	cameraID            = "cam-001"
	cameraPublicKeyPath = "artifacts/keys/camera_public.pem"
	cameraCertPath      = "artifacts/certs/camera.crt"
)

func main() {
	rootCA, err := authcrypto.LoadFactoryRootCA(rootCertPath, rootKeyPath)
	if err != nil {
		log.Fatalf("load root ca: %v", err)
	}

	cameraPublicKey, err := authcrypto.LoadRSAPublicKey(cameraPublicKeyPath)
	if err != nil {
		log.Fatalf("load camera public key: %v", err)
	}

	cameraCert, err := authcrypto.IssueCameraCertificate(rootCA, cameraID, cameraPublicKey)
	if err != nil {
		log.Fatalf("issue camera certificate: %v", err)
	}

	if err := authcrypto.SaveCertificate(cameraCert, cameraCertPath); err != nil {
		log.Fatalf("save camera certificate: %v", err)
	}

	log.Printf("camera certificate issued successfully: %s", cameraCertPath)
}
