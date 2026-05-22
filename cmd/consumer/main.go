package main

import (
	"context"
	"crypto-stream-auth/internal/app/consumer"
	"log"
	"time"
)

const (
	serverAddr = "127.0.0.1:4343"
	rootCAPath = "artifacts/certs/root_ca.crt"
	ffplayPath = "ffplay"

	handshakeTimeout   = 5 * time.Second
	maxHandshakeAge    = 10 * time.Second
	maxFrameAge        = 5 * time.Second
	maxSessionAttempts = 2
	idleTimeout        = 30 * time.Second
)

func main() {
	client, err := consumer.New(consumer.Options{
		ServerAddr:         serverAddr,
		RootCAPath:         rootCAPath,
		FFplayPath:         ffplayPath,
		HandshakeTimeout:   handshakeTimeout,
		MaxHandshakeAge:    maxHandshakeAge,
		MaxFrameAge:        maxFrameAge,
		MaxSessionAttempts: maxSessionAttempts,
		IdleTimeout:        idleTimeout,
		PolicyWindow:       3 * time.Second,
		PolicyMinFrames:    30,
		PolicyBadRatio:     0.2,
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
