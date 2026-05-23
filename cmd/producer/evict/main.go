package main

import (
	"flag"
	"log"

	"crypto-stream-auth/internal/tpm"
)

func main() {
	confirm := flag.Bool("confirm", false, "confirm camera key eviction")
	flag.Parse()

	if !*confirm {
		log.Fatalf("refuse to evict TPM key 0x%x without --confirm", tpm.DefaultCameraKeyHandle)
	}

	if err := tpm.EvictSigner(tpm.DefaultCameraKeyHandle, nil); err != nil {
		log.Fatalf("evict TPM camera key 0x%x: %v", tpm.DefaultCameraKeyHandle, err)
	}

	log.Printf("TPM camera key evicted: 0x%x", tpm.DefaultCameraKeyHandle)
	log.Printf("old camera certificate is no longer valid")
}
