package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"log"
	"time"

	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/tpm"
	"crypto-stream-auth/internal/transport"

	quic "github.com/quic-go/quic-go"
)

const (
	listenAddr     = "127.0.0.1:4242"
	cameraCertPath = "artifacts/certs/camera.crt"

	cameraKeyHandle uint32 = 0x81000001

	handshakeTimeout       = 5 * time.Second
	idleTimeout            = 30 * time.Second
	handshakeFailedCode    = quic.ApplicationErrorCode(1)
	handshakeCompletedCode = quic.ApplicationErrorCode(0)
)

func main() {
	cameraCertificate, err := authcrypto.LoadCertificate(cameraCertPath)
	if err != nil {
		log.Fatalf("load camera certificate: %v", err)
	}

	signer, err := tpm.OpenSigner(cameraKeyHandle, nil)
	if err != nil {
		log.Fatalf("open tpm signer: %v", err)
	}
	defer signer.Close()

	tlsConfig, err := transport.NewLocalServerTLSConfig()
	if err != nil {
		log.Fatalf("create quic tls config: %v", err)
	}

	listener, err := transport.Listen(listenAddr, tlsConfig, quicConfig())
	if err != nil {
		log.Fatalf("listen quic: %v", err)
	}
	defer listener.Close()

	log.Printf("producer listening on %s", listenAddr)

	for {
		if err := handleConnection(listener, cameraCertificate, signer); err != nil {
			log.Printf("handle connection: %v", err)
		}
	}
}

func handleConnection(listener *quic.Listener, cameraCertificate *x509.Certificate, signer handshake.RSAPSSSigner) (err error) {
	conn, err := transport.AcceptConnection(context.Background(), listener)
	if err != nil {
		return err
	}
	defer func() {
		code := handshakeFailedCode
		reason := "handshake failed"
		if err == nil {
			code = handshakeCompletedCode
			reason = "handshake complete"
		}

		if closeErr := conn.CloseWithError(code, reason); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()

	stream, err := transport.AcceptHandshakeStream(ctx, conn)
	if err != nil {
		return err
	}

	request, err := transport.ReadHandshakeRequest(ctx, stream)
	if err != nil {
		return err
	}

	response, session, err := handshake.BuildResponse(request, cameraCertificate, signer)
	if err != nil {
		return err
	}

	if err := transport.WriteHandshakeResponse(stream, response); err != nil {
		return err
	}

	log.Printf("handshake ok: session_id=%s", hex.EncodeToString(session.SessionID[:]))
	return nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       idleTimeout,
		MaxIncomingStreams:   4,
	}
}
