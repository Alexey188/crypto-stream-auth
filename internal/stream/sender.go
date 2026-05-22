package stream

import (
	"context"
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/domain"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/media"
	"crypto-stream-auth/internal/transport"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	quic "github.com/quic-go/quic-go"
)

func SendSignedFrames(ctx context.Context, conn *quic.Conn, session *handshake.ProducerSession, source media.Source) error {
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
			_ = frameStreams[streamIndex].Close()
			return fmt.Errorf("write frame %d to media stream %d: %w", sequence, streamIndex, err)
		}

		log.Printf("frame sent: session_id=%s sequence=%d media_stream=%d payload_bytes=%d",
			hex.EncodeToString(frame.SessionID[:]),
			frame.Sequence,
			streamIndex,
			len(frame.Payload),
		)

		select {
		case <-ctx.Done():
			return fmt.Errorf("send frames: %w", ctx.Err())
		default:
		}
	}
}
