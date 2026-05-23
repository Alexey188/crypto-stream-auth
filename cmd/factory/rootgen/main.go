package main

import (
	"log"

	authcrypto "crypto-stream-auth/internal/crypto"
)

const (
	orgName      = "TrustCam"
	rootCertPath = "artifacts/trust/roots/root_ca2.crt"
	rootKeyPath  = "artifacts/keys/root_ca2.key"
)

func main() {
	rootCA, err := authcrypto.GenerateRootCA(orgName)
	if err != nil {
		log.Fatal(err)
	}

	if err := authcrypto.SaveRootCA(rootCA, rootCertPath, rootKeyPath); err != nil {
		log.Fatal(err)
	}

	log.Printf("root ca generated successfully: cert=%s key=%s", rootCertPath, rootKeyPath)
}
