package main

import (
	"context"
	"crypto-stream-auth/internal/app/server"
	"log"
	"time"
)

const (
	listenAddr       = "127.0.0.1:4343"
	producerAddr     = "127.0.0.1:4242"
	rootCAPath       = "artifacts/certs/root_ca.crt"
	handshakeTimeout = 5 * time.Second
	idleTimeout      = 30 * time.Second
)

func main() {
	srv, err := server.New(server.Options{
		ListenAddr:       listenAddr,
		ProducerAddr:     producerAddr,
		RootCAPath:       rootCAPath,
		HandshakeTimeout: handshakeTimeout,
		IdleTimeout:      idleTimeout,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()

	if err := srv.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
