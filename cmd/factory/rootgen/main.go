package main

import (
	"log"

	authcrypto "crypto-stream-auth/internal/crypto"
)

const (
	orgName      = "TrustCam"
	rootCertPath = "certs/root_ca.crt"
	rootKeyPath  = "certs/root_ca.key"
)

func main() {
	rootCA, err := authcrypto.GenerateRootCA(orgName)
	if err != nil {
		log.Fatal(err)
	}

	if err := authcrypto.SaveRootCA(rootCA, rootCertPath, rootKeyPath); err != nil {
		log.Fatal(err)
	}
}
