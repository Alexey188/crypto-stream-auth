package server

import (
	"context"
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/transport"
	"crypto/x509"
	"fmt"
	"log"
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
	RootCAPath       string
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
}

type Server struct {
	options  Options
	rootCA   *x509.Certificate
	listener *quic.Listener
}

func New(options Options) (*Server, error) {
	rootCA, err := authcrypto.LoadCertificate(options.RootCAPath)
	if err != nil {
		return nil, fmt.Errorf("load root ca certificate: %w", err)
	}

	return &Server{
		options: options,
		rootCA:  rootCA,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("server is nil")
	}

	tlsConfig, err := transport.NewLocalServerTLSConfig()
	if err != nil {
		return fmt.Errorf("create quic tls config: %w", err)
	}

	quicConfig := transport.NewQUICConfig(s.options.HandshakeTimeout, s.options.IdleTimeout, transport.MediaStreamCount+1)
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

	producerConn, err := s.forwardHandshake(handshakeCtx, consumerStream, request)
	if err != nil {
		return err
	}
	defer transport.CloseSession(producerConn, &err, handshakeFailedCode, handshakeCompletedCode)

	log.Printf("handshake routed")

	return ForwardFrames(sessionCtx, producerConn, consumerConn)
}

func (s *Server) forwardHandshake(ctx context.Context, consumerStream *quic.Stream, request *handshake.Request) (*quic.Conn, error) {
	quicConfig := transport.NewQUICConfig(s.options.HandshakeTimeout, s.options.IdleTimeout, transport.MediaStreamCount+1)
	response, producerConn, err := RequestProducerHandshake(ctx, s.options.ProducerAddr, request, quicConfig, handshakeFailedCode)
	if err != nil {
		return nil, err
	}

	if err := VerifyCameraCertificate(response, s.rootCA); err != nil {
		_ = producerConn.CloseWithError(handshakeFailedCode, "handshake failed")
		return nil, err
	}

	if err := transport.WriteHandshakeResponse(consumerStream, response); err != nil {
		_ = producerConn.CloseWithError(handshakeFailedCode, "handshake failed")
		return nil, err
	}

	return producerConn, nil
}
