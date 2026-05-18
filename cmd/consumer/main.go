package main

import (
	"context"
	"encoding/hex"
	"log"
	"time"

	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/transport"

	quic "github.com/quic-go/quic-go"
)

const (
	serverAddr = "127.0.0.1:4343"
	rootCAPath = "artifacts/certs/root_ca.crt"

	handshakeTimeout = 5 * time.Second
	maxHandshakeAge  = 10 * time.Second
	idleTimeout      = 30 * time.Second
)

func main() {
	rootCA, err := authcrypto.LoadCertificate(rootCAPath)
	if err != nil {
		log.Fatalf("load root ca certificate: %v", err)
	}

	request, err := handshake.NewRequest()
	if err != nil {
		log.Fatalf("create handshake request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()

	conn, err := transport.Dial(ctx, serverAddr, transport.NewLocalClientTLSConfig(), quicConfig())
	if err != nil {
		log.Fatalf("dial server: %v", err)
	}
	defer conn.CloseWithError(0, "consumer done")

	stream, err := transport.OpenHandshakeStream(ctx, conn)
	if err != nil {
		log.Fatalf("open handshake stream: %v", err)
	}

	if err := transport.WriteHandshakeRequest(stream, request); err != nil {
		log.Fatalf("write handshake request: %v", err)
	}

	response, err := transport.ReadHandshakeResponse(ctx, stream)
	if err != nil {
		log.Fatalf("read handshake response: %v", err)
	}

	session, err := handshake.VerifyResponse(response, rootCA, request, maxHandshakeAge)
	if err != nil {
		log.Fatalf("verify handshake response: %v", err)
	}

	log.Printf("handshake ok: session_id=%s", hex.EncodeToString(session.SessionID[:]))
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       idleTimeout,
		MaxIncomingStreams:   4,
	}
}
