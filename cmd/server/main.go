package main

import (
	"context"
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

	response, err := requestProducerHandshake(ctx, request)
	if err != nil {
		return err
	}

	if err := transport.WriteHandshakeResponse(consumerStream, response); err != nil {
		return err
	}

	log.Printf("handshake routed")
	return nil
}

func requestProducerHandshake(ctx context.Context, request *handshake.Request) (*handshake.Response, error) {
	producerConn, err := transport.Dial(ctx, producerAddr, transport.NewLocalClientTLSConfig(), quicConfig())
	if err != nil {
		return nil, err
	}
	defer producerConn.CloseWithError(handshakeCompletedCode, "server done")

	producerStream, err := transport.OpenHandshakeStream(ctx, producerConn)
	if err != nil {
		return nil, err
	}

	if err := transport.WriteHandshakeRequest(producerStream, request); err != nil {
		return nil, err
	}

	return transport.ReadHandshakeResponse(ctx, producerStream)
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
		MaxIncomingStreams:   4,
	}
}
