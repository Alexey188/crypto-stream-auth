package consumer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/media"
	streamauth "crypto-stream-auth/internal/stream"
	"crypto-stream-auth/internal/transport"
)

type Options struct {
	ServerAddr         string
	TrustDir           string
	FFplayPath         string
	HandshakeTimeout   time.Duration
	MaxHandshakeAge    time.Duration
	MaxSessionAttempts int
	IdleTimeout        time.Duration
	PolicyWindow       time.Duration
	PolicyMinFrames    int
	PolicyBadRatio     float64
}

type Consumer struct {
	options    Options
	trustStore *authcrypto.TrustStore
}

func New(options Options) (*Consumer, error) {
	options = withDefaults(options)

	trustStore, err := authcrypto.LoadTrustStore(options.TrustDir)
	if err != nil {
		return nil, fmt.Errorf("load trust store: %w", err)
	}

	return &Consumer{
		options:    options,
		trustStore: trustStore,
	}, nil
}

func withDefaults(options Options) Options {
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = 5 * time.Second
	}
	if options.MaxHandshakeAge <= 0 {
		options.MaxHandshakeAge = 10 * time.Second
	}
	if options.MaxSessionAttempts <= 0 {
		options.MaxSessionAttempts = 2
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = 30 * time.Second
	}
	if options.PolicyWindow <= 0 {
		options.PolicyWindow = 3 * time.Second
	}
	if options.PolicyMinFrames <= 0 {
		options.PolicyMinFrames = 30
	}
	if options.PolicyBadRatio <= 0 {
		options.PolicyBadRatio = 0.2
	}
	return options
}

func (c *Consumer) Run(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("consumer is nil")
	}

	for attempt := 1; attempt <= c.options.MaxSessionAttempts; attempt++ {
		if err := c.runSession(ctx); err != nil {
			if errors.Is(err, streamauth.ErrRehandshakeRequired) && attempt < c.options.MaxSessionAttempts {
				log.Printf("frame policy action: rehandshake requested")
				continue
			}
			if errors.Is(err, streamauth.ErrRehandshakeRequired) {
				return fmt.Errorf("%w: repeated bad signatures after rehandshake", streamauth.ErrUntrustedConnection)
			}
			return err
		}
		return nil
	}

	return nil
}

func (c *Consumer) runSession(parentCtx context.Context) error {
	sessionCtx, sessionCancel := context.WithCancel(parentCtx)
	defer sessionCancel()

	request, err := handshake.NewRequest()
	if err != nil {
		return fmt.Errorf("create handshake request: %w\n", err)
	}
	log.Printf("handshake request created:\n  protocol_version=%d\n  consumer_nonce=%s",
		request.ProtocolVersion,
		hex.EncodeToString(request.ConsumerNonce[:]),
	)

	handshakeCtx, handshakeCancel := context.WithTimeout(sessionCtx, c.options.HandshakeTimeout)
	defer handshakeCancel()

	quicConfig := transport.NewQUICConfig(c.options.HandshakeTimeout, c.options.IdleTimeout)
	conn, err := transport.Dial(handshakeCtx, c.options.ServerAddr, transport.NewLocalClientTLSConfig(), quicConfig)
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	defer conn.CloseWithError(0, "consumer done")

	stream, err := transport.OpenStream(handshakeCtx, conn)
	if err != nil {
		return fmt.Errorf("open handshake stream: %w", err)
	}

	if err := transport.WriteHandshakeRequest(stream, request); err != nil {
		return fmt.Errorf("write handshake request: %w", err)
	}

	response, err := transport.ReadHandshakeResponse(handshakeCtx, stream)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}
	log.Printf("handshake response received:\n  session_id=%s\n  certificate_sha256=%s\n  ephemeral_public_key=%s\n  timestamp=%d\n  signature_bytes=%d",
		hex.EncodeToString(response.SessionID[:]),
		authcrypto.SHA256Hex(response.CameraCertificateDER),
		hex.EncodeToString(response.EphemeralPublicKey),
		response.Timestamp,
		len(response.Signature),
	)

	session, err := handshake.VerifyResponseWithTrustStore(response, c.trustStore, request, c.options.MaxHandshakeAge)
	if err != nil {
		return fmt.Errorf("verify handshake response: %w", err)
	}

	cameraUID, err := authcrypto.ExtractCameraUID(session.CameraCertificate)
	if err != nil {
		return fmt.Errorf("extract camera uid: %w", err)
	}
	log.Printf("handshake response verified:\n  session_id=%s\n  camera_id=%s\n  camera_uid=%s",
		hex.EncodeToString(session.SessionID[:]),
		session.CameraCertificate.Subject.CommonName,
		cameraUID,
	)

	log.Printf("handshake ok:\n")

	sink, err := media.NewFFplaySink(sessionCtx, c.options.FFplayPath)
	if err != nil {
		return fmt.Errorf("create live video sink: %w", err)
	}
	defer func() {
		if err := sink.Close(); err != nil {
			log.Printf("close live video sink: %v", err)
		}
	}()

	log.Printf("playing live video stream")

	if err := streamauth.ReceiveAndValidateFrames(sessionCtx, conn, session, streamauth.ReceiveOptions{
		PolicyWindow:      c.options.PolicyWindow,
		PolicyMinFrames:   c.options.PolicyMinFrames,
		PolicyBadRatio:    c.options.PolicyBadRatio,
		OnAcceptedPayload: sink.WritePayload,
	}); err != nil {
		return fmt.Errorf("receive frames: %w", err)
	}

	return nil
}
