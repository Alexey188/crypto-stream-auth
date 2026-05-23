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
	MediaSource      media.FFmpegSourceConfig
}

type Producer struct {
	options           Options
	cameraCertificate *x509.Certificate
	signer            *tpm.Signer
	signerMu          sync.Mutex
	sessionMu         sync.Mutex
	activeSession     *handshake.ProducerSession
	listener          *quic.Listener
}

func New(options Options) (*Producer, error) {
	options = withDefaults(options)

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

func withDefaults(options Options) Options {
	if options.CameraKeyHandle == 0 {
		options.CameraKeyHandle = tpm.DefaultCameraKeyHandle
	}
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = 5 * time.Second
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = 30 * time.Second
	}
	return options
}

func (p *Producer) Run(ctx context.Context) error {
	if p == nil {
		return fmt.Errorf("producer is nil")
	}

	tlsConfig, err := transport.NewLocalServerTLSConfig()
	if err != nil {
		return fmt.Errorf("create quic tls config: %w", err)
	}

	quicConfig := transport.NewQUICConfig(p.options.HandshakeTimeout, p.options.IdleTimeout)
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
	log.Printf("handshake request received:\n  protocol_version=%d\n  consumer_nonce=%s",
		request.ProtocolVersion,
		hex.EncodeToString(request.ConsumerNonce[:]),
	)

	response, session, startsMedia, err := p.buildHandshakeResponse(request)
	if err != nil {
		return err
	}
	log.Printf("handshake response built:\n  session_id=%s\n  certificate_subject=%q\n  certificate_sha256=%s\n  ephemeral_public_key=%s\n  timestamp=%d\n  signature_bytes=%d",
		hex.EncodeToString(response.SessionID[:]),
		p.cameraCertificate.Subject.CommonName,
		authcrypto.SHA256Hex(response.CameraCertificateDER),
		hex.EncodeToString(response.EphemeralPublicKey),
		response.Timestamp,
		len(response.Signature),
	)

	if err := transport.WriteHandshakeResponse(stream, response); err != nil {
		return err
	}

	if !startsMedia {
		log.Printf("handshake ok:\n  mode=existing_media_session")
		return nil
	}
	defer p.clearActiveSession(session)

	log.Printf("handshake ok:\n  mode=new_media_session")

	source, err := media.NewFFmpegSource(sessionCtx, p.options.MediaSource)
	if err != nil {
		return fmt.Errorf("create media source: %w", err)
	}
	defer source.Close()

	return streamauth.SendSignedFrames(sessionCtx, conn, session, source)
}

func (p *Producer) buildHandshakeResponse(request *handshake.Request) (*handshake.Response, *handshake.ProducerSession, bool, error) {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()

	if p.activeSession != nil {
		response, err := handshake.BuildResponseForSession(request, p.cameraCertificate, p, p.activeSession)
		if err != nil {
			return nil, nil, false, err
		}
		return response, p.activeSession, false, nil
	}

	response, session, err := handshake.BuildResponse(request, p.cameraCertificate, p)
	if err != nil {
		return nil, nil, false, err
	}

	p.activeSession = session
	return response, session, true, nil
}

func (p *Producer) clearActiveSession(session *handshake.ProducerSession) {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()

	if p.activeSession == session {
		p.activeSession = nil
	}
}
