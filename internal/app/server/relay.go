package server

import (
	"context"
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/transport"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	quic "github.com/quic-go/quic-go"
)

func RequestProducerHandshake(ctx context.Context, producerAddr string, request *handshake.Request, quicConfig *quic.Config, failedCode quic.ApplicationErrorCode) (*handshake.Response, *quic.Conn, error) {
	producerConn, err := transport.Dial(ctx, producerAddr, transport.NewLocalClientTLSConfig(), quicConfig)
	if err != nil {
		return nil, nil, err
	}

	producerStream, err := transport.OpenStream(ctx, producerConn)
	if err != nil {
		_ = producerConn.CloseWithError(failedCode, "handshake failed")
		return nil, nil, err
	}

	if err := transport.WriteHandshakeRequest(producerStream, request); err != nil {
		_ = producerConn.CloseWithError(failedCode, "handshake failed")
		return nil, nil, err
	}

	response, err := transport.ReadHandshakeResponse(ctx, producerStream)
	if err != nil {
		_ = producerConn.CloseWithError(failedCode, "handshake failed")
		return nil, nil, err
	}

	return response, producerConn, nil
}

func VerifyCameraCertificate(response *handshake.Response, rootCA *x509.Certificate) error {
	if response == nil {
		return fmt.Errorf("camera certificate response is nil")
	}

	cameraCertificate, err := x509.ParseCertificate(response.CameraCertificateDER)
	if err != nil {
		return fmt.Errorf("parse camera certificate: %w", err)
	}

	if _, err := authcrypto.VerifyCameraCertificate(cameraCertificate, rootCA); err != nil {
		return fmt.Errorf("verify camera certificate: %w", err)
	}

	return nil
}

func ForwardFrames(ctx context.Context, producerConn *quic.Conn, consumerConn *quic.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	producerStreams := make([]*quic.Stream, transport.MediaStreamCount)
	for i := range producerStreams {
		producerStream, err := transport.AcceptStream(ctx, producerConn)
		if err != nil {
			return fmt.Errorf("accept producer media stream %d: %w", i, err)
		}
		producerStreams[i] = producerStream
	}
	defer closeStreams(producerStreams)

	consumerStreams := make([]*quic.Stream, transport.MediaStreamCount)
	for i := range consumerStreams {
		consumerStream, err := transport.OpenStream(ctx, consumerConn)
		if err != nil {
			return fmt.Errorf("open consumer media stream %d: %w", i, err)
		}
		consumerStreams[i] = consumerStream
	}
	defer closeStreams(consumerStreams)

	statsWindowStarted := time.Now()
	var statsFrames uint64
	var statsPayloadBytes uint64

	for result := range transport.ReadFramesFromStreams(ctx, producerStreams) {
		if result.Err != nil {
			if errors.Is(result.Err, io.EOF) || transport.IsGracefulRemoteClose(result.Err) {
				log.Printf("producer media stream finished")
				return nil
			}
			return fmt.Errorf("read producer frame from media stream %d: %w", result.StreamIndex, result.Err)
		}

		if err := transport.WriteFrame(consumerStreams[result.StreamIndex], result.Frame); err != nil {
			_ = consumerStreams[result.StreamIndex].Close()
			return fmt.Errorf("write consumer frame to media stream %d: %w", result.StreamIndex, err)
		}

		statsFrames++
		statsPayloadBytes += uint64(len(result.Frame.Payload))

		now := time.Now()
		if now.Sub(statsWindowStarted) >= time.Second {
			elapsed := now.Sub(statsWindowStarted).Seconds()
			avgPayload := uint64(0)
			if statsFrames > 0 {
				avgPayload = statsPayloadBytes / statsFrames
			}
			log.Printf("server relay stats: frames=%d bytes=%d fps=%.1f avg_payload=%d",
				statsFrames,
				statsPayloadBytes,
				float64(statsFrames)/elapsed,
				avgPayload,
			)

			statsWindowStarted = now
			statsFrames = 0
			statsPayloadBytes = 0
		}
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("forward frames: %w", err)
	}
	return nil
}

func closeStreams(streams []*quic.Stream) {
	for _, stream := range streams {
		if stream != nil {
			_ = stream.Close()
		}
	}
}
