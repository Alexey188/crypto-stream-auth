package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/handshake"
	streamauth "crypto-stream-auth/internal/stream"
	"crypto-stream-auth/internal/transport"

	quic "github.com/quic-go/quic-go"
)

const (
	serverAddr = "127.0.0.1:4343"
	rootCAPath = "artifacts/certs/root_ca.crt"

	handshakeTimeout    = 5 * time.Second
	frameReceiveTimeout = 10 * time.Second
	maxHandshakeAge     = 10 * time.Second
	maxFrameAge         = 5 * time.Second
	demoFrameCount      = 40
	maxSessionAttempts  = 2
	idleTimeout         = 30 * time.Second
)

var (
	errRehandshakeRequired = errors.New("rehandshake required")
	errUntrustedConnection = errors.New("untrusted connection")
)

func main() {
	rootCA, err := authcrypto.LoadCertificate(rootCAPath)
	if err != nil {
		log.Fatalf("load root ca certificate: %v", err)
	}

	for attempt := 1; attempt <= maxSessionAttempts; attempt++ {
		if err := runSession(rootCA); err != nil {
			if errors.Is(err, errRehandshakeRequired) && attempt < maxSessionAttempts {
				log.Printf("frame policy action: rehandshake requested")
				continue
			}
			if errors.Is(err, errRehandshakeRequired) {
				log.Fatalf("%v: repeated bad signatures after rehandshake", errUntrustedConnection)
			}
			log.Fatalf("session failed: %v", err)
		}
		return
	}
}

func runSession(rootCA *x509.Certificate) error {
	request, err := handshake.NewRequest()
	if err != nil {
		return fmt.Errorf("create handshake request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()

	conn, err := transport.Dial(ctx, serverAddr, transport.NewLocalClientTLSConfig(), quicConfig())
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	defer conn.CloseWithError(0, "consumer done")

	stream, err := transport.OpenHandshakeStream(ctx, conn)
	if err != nil {
		return fmt.Errorf("open handshake stream: %w", err)
	}

	if err := transport.WriteHandshakeRequest(stream, request); err != nil {
		return fmt.Errorf("write handshake request: %w", err)
	}

	response, err := transport.ReadHandshakeResponse(ctx, stream)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	session, err := handshake.VerifyResponse(response, rootCA, request, maxHandshakeAge)
	if err != nil {
		return fmt.Errorf("verify handshake response: %w", err)
	}

	log.Printf("handshake ok: session_id=%s", hex.EncodeToString(session.SessionID[:]))

	frameCtx, frameCancel := context.WithTimeout(context.Background(), frameReceiveTimeout)
	defer frameCancel()

	if err := receiveFrames(frameCtx, conn, session); err != nil {
		return fmt.Errorf("receive frames: %w", err)
	}

	return nil
}

func receiveFrames(ctx context.Context, conn *quic.Conn, session *handshake.ConsumerSession) error {
	validator, err := streamauth.NewFrameValidator(session.SessionID, session.EphemeralPublicKey, maxFrameAge)
	if err != nil {
		return fmt.Errorf("create frame validator: %w", err)
	}

	policy, err := streamauth.NewFramePolicy(3*time.Second, 30, 0.2)
	if err != nil {
		return fmt.Errorf("create frame policy: %w", err)
	}

	for i := 0; i < demoFrameCount; i++ {
		frameStream, err := transport.AcceptStream(ctx, conn)
		if err != nil {
			return fmt.Errorf("accept frame stream: %w", err)
		}

		frame, err := transport.ReadFrame(ctx, frameStream)
		if err != nil {
			_ = frameStream.Close()
			return fmt.Errorf("read frame: %w", err)
		}
		_ = frameStream.Close()

		err = validator.ValidateFrame(frame)
		signatureInvalid := errors.Is(err, streamauth.ErrInvalidFrameSignature)
		action := policy.RecordFrame(signatureInvalid, time.Now())

		if err != nil {
			log.Printf("frame dropped: sequence=%d reason=%v", frame.Sequence, err)
		} else {
			log.Printf("frame accepted: sequence=%d payload_bytes=%d", frame.Sequence, len(frame.Payload))
		}

		switch action {
		case streamauth.FramePolicyActionRehandshake:
			return errRehandshakeRequired
		case streamauth.FramePolicyActionDropConnection:
			return errUntrustedConnection
		}
	}

	return nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       idleTimeout,
		MaxIncomingStreams:   demoFrameCount + 1,
	}
}
