package main

import (
	"context"
	"crypto-stream-auth/internal/app/consumer"
	"log"
)

const (
	serverAddr = "127.0.0.1:4343"
	trustDir   = "artifacts/trust"
	ffplayPath = "ffplay"
)

func main() {
	client, err := consumer.New(consumer.Options{
		ServerAddr: serverAddr,
		TrustDir:   trustDir,
		FFplayPath: ffplayPath,
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
