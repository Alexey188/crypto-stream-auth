package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/transport"

	quic "github.com/quic-go/quic-go"
)

const (
	listenAddr   = "127.0.0.1:4343"
	producerAddr = "127.0.0.1:4242"

	handshakeTimeout       = 5 * time.Second
	frameForwardTimeout    = 10 * time.Second
	demoFrameCount         = 40
	idleTimeout            = 30 * time.Second
	handshakeFailedCode    = quic.ApplicationErrorCode(1)
	handshakeCompletedCode = quic.ApplicationErrorCode(0)
)

func main() {
	tlsConfig, err := transport.NewLocalServerTLSConfig()
	if err != nil {
		log.Fatalf("create quic tls config: %v", err)
	}

	listener, err := transport.Listen(listenAddr, tlsConfig, quicConfig())
	if err != nil {
		log.Fatalf("listen quic: %v", err)
	}
	defer listener.Close()

	log.Printf("server listening on %s", listenAddr)
	log.Printf("producer upstream: %s", producerAddr)

	for {
		conn, err := transport.AcceptConnection(context.Background(), listener)
		if err != nil {
			log.Printf("accept consumer connection: %v", err)
			continue
		}

		go func() {
			if err := handleConsumerConnection(conn); err != nil {
				log.Printf("handle consumer connection: %v", err)
			}
		}()
	}
}

func handleConsumerConnection(consumerConn *quic.Conn) (err error) {
	defer closeConnection(consumerConn, &err)

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()

	consumerStream, err := transport.AcceptHandshakeStream(ctx, consumerConn)
	if err != nil {
		return err
	}

	request, err := transport.ReadHandshakeRequest(ctx, consumerStream)
	if err != nil {
		return err
	}

	response, producerConn, err := requestProducerHandshake(ctx, request)
	if err != nil {
		return err
	}
	defer closeConnection(producerConn, &err)

	if err := transport.WriteHandshakeResponse(consumerStream, response); err != nil {
		return err
	}

	log.Printf("handshake routed")

	frameCtx, frameCancel := context.WithTimeout(context.Background(), frameForwardTimeout)
	defer frameCancel()

	return forwardFrames(frameCtx, producerConn, consumerConn)
}

func requestProducerHandshake(ctx context.Context, request *handshake.Request) (*handshake.Response, *quic.Conn, error) {
	producerConn, err := transport.Dial(ctx, producerAddr, transport.NewLocalClientTLSConfig(), quicConfig())
	if err != nil {
		return nil, nil, err
	}

	producerStream, err := transport.OpenHandshakeStream(ctx, producerConn)
	if err != nil {
		_ = producerConn.CloseWithError(handshakeFailedCode, "handshake failed")
		return nil, nil, err
	}

	if err := transport.WriteHandshakeRequest(producerStream, request); err != nil {
		_ = producerConn.CloseWithError(handshakeFailedCode, "handshake failed")
		return nil, nil, err
	}

	response, err := transport.ReadHandshakeResponse(ctx, producerStream)
	if err != nil {
		_ = producerConn.CloseWithError(handshakeFailedCode, "handshake failed")
		return nil, nil, err
	}

	return response, producerConn, nil
}

func forwardFrames(ctx context.Context, producerConn *quic.Conn, consumerConn *quic.Conn) error {
	for i := 0; i < demoFrameCount; i++ {
		producerStream, err := transport.AcceptStream(ctx, producerConn)
		if err != nil {
			return fmt.Errorf("accept producer frame stream: %w", err)
		}

		frame, err := transport.ReadFrame(ctx, producerStream)
		if err != nil {
			_ = producerStream.Close()
			return fmt.Errorf("read producer frame: %w", err)
		}
		_ = producerStream.Close()

		consumerStream, err := transport.OpenStream(ctx, consumerConn)
		if err != nil {
			return fmt.Errorf("open consumer frame stream: %w", err)
		}

		if err := transport.WriteFrame(consumerStream, frame); err != nil {
			_ = consumerStream.Close()
			return fmt.Errorf("write consumer frame: %w", err)
		}

		if err := consumerStream.Close(); err != nil {
			return fmt.Errorf("close consumer frame stream: %w", err)
		}

		log.Printf("frame routed: sequence=%d payload_bytes=%d", frame.Sequence, len(frame.Payload))
	}

	return nil
}

func closeConnection(conn *quic.Conn, handlerErr *error) {
	code := handshakeFailedCode
	reason := "handshake failed"
	if *handlerErr == nil {
		code = handshakeCompletedCode
		reason = "handshake complete"
	}

	if closeErr := conn.CloseWithError(code, reason); *handlerErr == nil && closeErr != nil {
		*handlerErr = closeErr
	}
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       idleTimeout,
		MaxIncomingStreams:   demoFrameCount + 1,
	}
}
