package stream

import (
	"context"
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/domain"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/transport"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	quic "github.com/quic-go/quic-go"
)

type PayloadSource interface {
	NextPayload(ctx context.Context) ([]byte, error)
}

func SendSignedFrames(ctx context.Context, conn *quic.Conn, session *handshake.ProducerSession, source PayloadSource) error {
	if session == nil {
		return fmt.Errorf("%w: producer session is nil", ErrValidateFrame)
	}
	if source == nil {
		return fmt.Errorf("%w: media source is nil", ErrValidateFrame)
	}

	frameStreams := make([]*quic.Stream, transport.MediaStreamCount)
	for i := range frameStreams {
		frameStream, err := transport.OpenStream(ctx, conn)
		if err != nil {
			return fmt.Errorf("open media stream %d: %w", i, err)
		}
		frameStreams[i] = frameStream
	}
	defer func() {
		for _, frameStream := range frameStreams {
			_ = frameStream.Close()
		}
	}()

	statsWindowStarted := time.Now()
	var statsFrames uint64
	var statsPayloadBytes uint64

	for sequence := uint64(1); ; sequence++ {
		payload, err := source.NextPayload(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Printf("media source finished")
				return nil
			}
			return fmt.Errorf("read media payload %d: %w", sequence, err)
		}

		frame := &domain.VideoFrame{
			SessionID: session.SessionID,
			Sequence:  sequence,
			Timestamp: time.Now().Unix(),
			Payload:   payload,
		}

		if err := authcrypto.SignFrameSignature(session.EphemeralPrivateKey, frame); err != nil {
			return fmt.Errorf("sign frame %d: %w", sequence, err)
		}

		streamIndex := int((sequence - 1) % uint64(len(frameStreams)))

		if err := transport.WriteFrame(frameStreams[streamIndex], frame); err != nil {
			if transport.IsGracefulRemoteClose(err) {
				log.Printf("media stream finished")
				return nil
			}
			_ = frameStreams[streamIndex].Close()
			return fmt.Errorf("write frame %d to media stream %d: %w", sequence, streamIndex, err)
		}

		statsFrames++
		statsPayloadBytes += uint64(len(payload))

		now := time.Now()
		if now.Sub(statsWindowStarted) >= time.Second {
			elapsed := now.Sub(statsWindowStarted).Seconds()
			avgPayload := uint64(0)
			if statsFrames > 0 {
				avgPayload = statsPayloadBytes / statsFrames
			}
			log.Printf("producer stats: frames=%d bytes=%d fps=%.1f avg_payload=%d",
				statsFrames,
				statsPayloadBytes,
				float64(statsFrames)/elapsed,
				avgPayload,
			)

			statsWindowStarted = now
			statsFrames = 0
			statsPayloadBytes = 0
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("send frames: %w", ctx.Err())
		default:
		}
	}
}
