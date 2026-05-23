package main

import (
	"log"

	authcrypto "crypto-stream-auth/internal/crypto"
)

const (
	rootCertPath        = "artifacts/trust/roots/root_ca2.crt"
	rootKeyPath         = "artifacts/keys/root_ca2.key"
	cameraID            = "cam-001"
	cameraPublicKeyPath = "artifacts/camera/camera_public2.pem"
	cameraCertPath      = "artifacts/camera/camera2.crt"
	cameraManifestPath  = "artifacts/trust/camera_manifest.json"
)

func main() {
	factory, err := authcrypto.LoadFactoryAuthority(rootCertPath, rootKeyPath)
	if err != nil {
		log.Fatalf("load factory authority: %v", err)
	}

	cameraPublicKey, err := authcrypto.LoadRSAPublicKey(cameraPublicKeyPath)
	if err != nil {
		log.Fatalf("load camera public key: %v", err)
	}

	cameraCert, err := factory.IssueCameraCertificate(cameraID, cameraPublicKey)
	if err != nil {
		log.Fatalf("issue camera certificate: %v", err)
	}

	manifest, err := factory.NewCameraManifest(cameraCert)
	if err != nil {
		log.Fatalf("create camera manifest: %v", err)
	}

	if err := authcrypto.SaveCameraCertificateBundle(cameraCert, manifest, cameraCertPath, cameraManifestPath); err != nil {
		log.Fatalf("save camera certificate bundle: %v", err)
	}

	log.Printf("camera certificate issued successfully: cert=%s manifest=%s", cameraCertPath, cameraManifestPath)
}
