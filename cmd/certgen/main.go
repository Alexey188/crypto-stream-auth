package main

import (
	"crypto-stream-auth/internal/crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

func main() {

	certGenerator, err := crypto.NewCertificateGenerator("certs/root_ca.crt", "certs/root_ca.key", "TrustCam Corp")
	if err != nil {
		log.Fatalf("Ошибка создания/чтения сертификата и ключа: %v", err)
	}

	cameraID := fmt.Sprintf("Cam-%d", time.Now().Unix())

	camCert, camPrivKey, err := certGenerator.IssueCameraCertificate(cameraID)
	if err != nil {
		log.Fatalf("Ошибка выпуска сертификата: %v", err)
	}

	certFile, err := os.Create(filepath.Join("certs/", cameraID+".crt"))
	if err != nil {
		log.Fatalf("Ошибка создания файла сертификата: %v", err)
	}
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: camCert.Raw})
	defer certFile.Close()

	keyFile, err := os.OpenFile(filepath.Join("certs/"+cameraID+".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Ошибка создания файла ключа: %v", err)
	}
	privBytes, err := x509.MarshalECPrivateKey(camPrivKey)
	if err != nil {
		log.Fatalf("Ошибка маршалинга приватного ключа: %v", err)
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	defer keyFile.Close()

	fmt.Printf("Успешно созданы ключи для %s\n", cameraID)

}
