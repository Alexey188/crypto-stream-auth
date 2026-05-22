package consumer

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
	"crypto-stream-auth/internal/media"
	streamauth "crypto-stream-auth/internal/stream"
	"crypto-stream-auth/internal/transport"
)

type Options struct {
	ServerAddr         string
	RootCAPath         string
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
	options Options
	rootCA  *x509.Certificate
}

func New(options Options) (*Consumer, error) {
	rootCA, err := authcrypto.LoadCertificate(options.RootCAPath)
	if err != nil {
		return nil, fmt.Errorf("load root ca certificate: %w", err)
	}

	return &Consumer{
		options: options,
		rootCA:  rootCA,
	}, nil
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
		return fmt.Errorf("create handshake request: %w", err)
	}

	handshakeCtx, handshakeCancel := context.WithTimeout(sessionCtx, c.options.HandshakeTimeout)
	defer handshakeCancel()

	quicConfig := transport.NewQUICConfig(c.options.HandshakeTimeout, c.options.IdleTimeout, transport.MediaStreamCount+1)
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

	session, err := handshake.VerifyResponse(response, c.rootCA, request, c.options.MaxHandshakeAge)
	if err != nil {
		return fmt.Errorf("verify handshake response: %w", err)
	}

	log.Printf("handshake ok: session_id=%s", hex.EncodeToString(session.SessionID[:]))

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
