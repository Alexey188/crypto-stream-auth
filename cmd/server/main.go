package main

import (
	"context"
	"crypto-stream-auth/internal/app/server"
	"log"
)

const (
	listenAddr   = "127.0.0.1:4343"
	producerAddr = "127.0.0.1:4242"
	trustDir     = "artifacts/trust"
)

func main() {
	srv, err := server.New(server.Options{
		ListenAddr:   listenAddr,
		ProducerAddr: producerAddr,
		TrustDir:     trustDir,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()

	if err := srv.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
