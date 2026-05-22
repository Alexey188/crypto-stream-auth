package producer

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/media"
	streamauth "crypto-stream-auth/internal/stream"
	"crypto-stream-auth/internal/tpm"
	"crypto-stream-auth/internal/transport"

	quic "github.com/quic-go/quic-go"
)

const (
	handshakeFailedCode    = quic.ApplicationErrorCode(1)
	handshakeCompletedCode = quic.ApplicationErrorCode(0)
)

type Options struct {
	ListenAddr       string
	CameraCertPath   string
	CameraKeyHandle  uint32
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	MediaSource      media.FFmpegH264SourceConfig
}

type Producer struct {
	options           Options
	cameraCertificate *x509.Certificate
	signer            *tpm.Signer
	signerMu          sync.Mutex
	listener          *quic.Listener
}

func New(options Options) (*Producer, error) {
	cameraCertificate, err := authcrypto.LoadCertificate(options.CameraCertPath)
	if err != nil {
		return nil, fmt.Errorf("load camera certificate: %w", err)
	}

	signer, err := tpm.OpenSigner(options.CameraKeyHandle, nil)
	if err != nil {
		return nil, fmt.Errorf("open tpm signer: %w", err)
	}

	return &Producer{
		options:           options,
		cameraCertificate: cameraCertificate,
		signer:            signer,
	}, nil
}

func (p *Producer) Run(ctx context.Context) error {
	if p == nil {
		return fmt.Errorf("producer is nil")
	}

	tlsConfig, err := transport.NewLocalServerTLSConfig()
	if err != nil {
		return fmt.Errorf("create quic tls config: %w", err)
	}

	quicConfig := transport.NewQUICConfig(p.options.HandshakeTimeout, p.options.IdleTimeout, transport.MediaStreamCount+1)
	listener, err := transport.Listen(p.options.ListenAddr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("listen quic: %w", err)
	}
	p.listener = listener
	defer p.Close()

	log.Printf("producer listening on %s", p.options.ListenAddr)

	for {
		conn, err := transport.AcceptConnection(ctx, listener)
		if err != nil {
			return err
		}

		go func() {
			if err := p.handleConnection(ctx, conn); err != nil {
				log.Printf("handle connection: %v", err)
			}
		}()
	}
}

func (p *Producer) Close() error {
	if p == nil {
		return nil
	}

	var closeErr error
	if p.listener != nil {
		closeErr = p.listener.Close()
		p.listener = nil
	}
	if p.signer != nil {
		if err := p.signer.Close(); closeErr == nil && err != nil {
			closeErr = err
		}
		p.signer = nil
	}

	return closeErr
}

func (p *Producer) SignPSS(digest []byte) ([]byte, error) {
	p.signerMu.Lock()
	defer p.signerMu.Unlock()
	return p.signer.SignPSS(digest)
}

func (p *Producer) handleConnection(parentCtx context.Context, conn *quic.Conn) (err error) {
	sessionCtx, sessionCancel := context.WithCancel(parentCtx)
	defer sessionCancel()
	defer transport.CloseSession(conn, &err, handshakeFailedCode, handshakeCompletedCode)

	handshakeCtx, handshakeCancel := context.WithTimeout(sessionCtx, p.options.HandshakeTimeout)
	defer handshakeCancel()

	stream, err := transport.AcceptStream(handshakeCtx, conn)
	if err != nil {
		return err
	}

	request, err := transport.ReadHandshakeRequest(handshakeCtx, stream)
	if err != nil {
		return err
	}

	response, session, err := handshake.BuildResponse(request, p.cameraCertificate, p)
	if err != nil {
		return err
	}

	if err := transport.WriteHandshakeResponse(stream, response); err != nil {
		return err
	}

	log.Printf("handshake ok: session_id=%s", hex.EncodeToString(session.SessionID[:]))

	source, err := media.NewFFmpegH264Source(sessionCtx, p.options.MediaSource)
	if err != nil {
		return fmt.Errorf("create media source: %w", err)
	}
	defer source.Close()

	return streamauth.SendSignedFrames(sessionCtx, conn, session, source)
}
