package main

import (
	"flag"
	"log"

	"crypto-stream-auth/internal/tpm"
)

const cameraKeyHandle uint32 = 0x81000001

func main() {
	confirm := flag.Bool("confirm", false, "confirm camera key eviction")
	flag.Parse()

	if !*confirm {
		log.Fatalf("refuse to evict TPM key 0x%x without --confirm", cameraKeyHandle)
	}

	if err := tpm.EvictSigner(cameraKeyHandle, nil); err != nil {
		log.Fatalf("evict TPM camera key 0x%x: %v", cameraKeyHandle, err)
	}

	log.Printf("TPM camera key evicted: 0x%x", cameraKeyHandle)
	log.Printf("old camera certificate is no longer valid")

}
