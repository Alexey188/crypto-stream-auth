package server

import (
	"context"
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/transport"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	handshakeFailedCode    = quic.ApplicationErrorCode(1)
	handshakeCompletedCode = quic.ApplicationErrorCode(0)
)

type Options struct {
	ListenAddr       string
	ProducerAddr     string
	TrustDir         string
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
}

type Server struct {
	options    Options
	trustStore *authcrypto.TrustStore
	listener   *quic.Listener
	hubMu      sync.Mutex
	hub        *FrameHub
}

func New(options Options) (*Server, error) {
	options = withDefaults(options)

	trustStore, err := authcrypto.LoadTrustStore(options.TrustDir)
	if err != nil {
		return nil, fmt.Errorf("load trust store: %w", err)
	}

	return &Server{
		options:    options,
		trustStore: trustStore,
	}, nil
}

func withDefaults(options Options) Options {
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = 5 * time.Second
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = 30 * time.Second
	}
	return options
}

func (s *Server) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("server is nil")
	}

	tlsConfig, err := transport.NewLocalServerTLSConfig()
	if err != nil {
		return fmt.Errorf("create quic tls config: %w", err)
	}

	quicConfig := transport.NewQUICConfig(s.options.HandshakeTimeout, s.options.IdleTimeout)
	listener, err := transport.Listen(s.options.ListenAddr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("listen quic: %w", err)
	}
	s.listener = listener
	defer s.Close()

	log.Printf("server listening on %s", s.options.ListenAddr)
	log.Printf("producer upstream: %s", s.options.ProducerAddr)

	for {
		conn, err := transport.AcceptConnection(ctx, listener)
		if err != nil {
			return err
		}

		go func() {
			if err := s.handleConsumerConnection(ctx, conn); err != nil {
				log.Printf("handle consumer connection: %v", err)
			}
		}()
	}
}

func (s *Server) Close() error {
	if s == nil || s.listener == nil {
		return nil
	}

	err := s.listener.Close()
	s.listener = nil
	return err
}

func (s *Server) handleConsumerConnection(parentCtx context.Context, consumerConn *quic.Conn) (err error) {
	sessionCtx, sessionCancel := context.WithCancel(parentCtx)
	defer sessionCancel()
	defer transport.CloseSession(consumerConn, &err, handshakeFailedCode, handshakeCompletedCode)

	handshakeCtx, handshakeCancel := context.WithTimeout(sessionCtx, s.options.HandshakeTimeout)
	defer handshakeCancel()

	consumerStream, err := transport.AcceptStream(handshakeCtx, consumerConn)
	if err != nil {
		return err
	}

	request, err := transport.ReadHandshakeRequest(handshakeCtx, consumerStream)
	if err != nil {
		return err
	}
	log.Printf("handshake request from consumer:\n  protocol_version=%d\n  consumer_nonce=%s",
		request.ProtocolVersion,
		hex.EncodeToString(request.ConsumerNonce[:]),
	)

	response, mediaHub, err := s.prepareMediaHub(parentCtx, handshakeCtx, request)
	if err != nil {
		return err
	}

	subscription, err := mediaHub.AddConsumer(sessionCtx, consumerConn)
	if err != nil {
		return err
	}
	defer mediaHub.RemoveConsumer(subscription)

	if err := transport.WriteHandshakeResponse(consumerStream, response); err != nil {
		return err
	}

	mediaHub.Start(s.clearMediaHub)

	log.Printf("handshake routed:\n  session_id=%s", hex.EncodeToString(response.SessionID[:]))

	return subscription.Wait(sessionCtx)
}

func (s *Server) prepareMediaHub(parentCtx context.Context, handshakeCtx context.Context, request *handshake.Request) (*handshake.Response, *FrameHub, error) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()

	if s.hub != nil {
		response, producerConn, err := s.requestProducerHandshake(handshakeCtx, request)
		if err != nil {
			return nil, nil, err
		}
		_ = producerConn.CloseWithError(handshakeCompletedCode, "handshake complete")

		if response.SessionID != s.hub.SessionID() {
			return nil, nil, fmt.Errorf("producer returned another session id for active media session")
		}

		return response, s.hub, nil
	}

	response, producerConn, err := s.requestProducerHandshake(handshakeCtx, request)
	if err != nil {
		return nil, nil, err
	}

	s.hub = NewFrameHub(parentCtx, producerConn, response.SessionID)
	return response, s.hub, nil
}

func (s *Server) requestProducerHandshake(ctx context.Context, request *handshake.Request) (*handshake.Response, *quic.Conn, error) {
	quicConfig := transport.NewQUICConfig(s.options.HandshakeTimeout, s.options.IdleTimeout)
	response, producerConn, err := RequestProducerHandshake(ctx, s.options.ProducerAddr, request, quicConfig, handshakeFailedCode)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("handshake response from producer:\n  session_id=%s\n  certificate_sha256=%s\n  ephemeral_public_key=%s\n  timestamp=%d\n  signature_bytes=%d",
		hex.EncodeToString(response.SessionID[:]),
		authcrypto.SHA256Hex(response.CameraCertificateDER),
		hex.EncodeToString(response.EphemeralPublicKey),
		response.Timestamp,
		len(response.Signature),
	)

	if err := VerifyCameraCertificate(response, s.trustStore); err != nil {
		_ = producerConn.CloseWithError(handshakeFailedCode, "handshake failed")
		return nil, nil, err
	}
	log.Printf("camera certificate verified by server:\n  certificate_sha256=%s", authcrypto.SHA256Hex(response.CameraCertificateDER))

	return response, producerConn, nil
}

func (s *Server) clearMediaHub(hub *FrameHub) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()

	if s.hub == hub {
		s.hub = nil
	}
}
