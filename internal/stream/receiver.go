package stream

import (
	"context"
	"crypto-stream-auth/internal/handshake"
	"crypto-stream-auth/internal/transport"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	quic "github.com/quic-go/quic-go"
)

const maxReorderBufferFrames = transport.MediaStreamCount * 2

var (
	ErrRehandshakeRequired = errors.New("rehandshake required")
	ErrUntrustedConnection = errors.New("untrusted connection")
)

type ReceiveOptions struct {
	MaxFrameAge       time.Duration
	PolicyWindow      time.Duration
	PolicyMinFrames   int
	PolicyBadRatio    float64
	OnAcceptedPayload func([]byte) error
}

func ReceiveAndValidateFrames(ctx context.Context, conn *quic.Conn, session *handshake.ConsumerSession, options ReceiveOptions) error {
	if session == nil {
		return fmt.Errorf("%w: consumer session is nil", ErrValidateFrame)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	validator, err := NewFrameValidator(session.SessionID, session.EphemeralPublicKey, options.MaxFrameAge)
	if err != nil {
		return fmt.Errorf("create frame validator: %w", err)
	}

	policy, err := NewFramePolicy(options.PolicyWindow, options.PolicyMinFrames, options.PolicyBadRatio)
	if err != nil {
		return fmt.Errorf("create frame policy: %w", err)
	}

	frameStreams := make([]*quic.Stream, transport.MediaStreamCount)
	for i := range frameStreams {
		frameStream, err := transport.AcceptStream(ctx, conn)
		if err != nil {
			if transport.IsGracefulRemoteClose(err) {
				log.Printf("media stream finished")
				return nil
			}
			return fmt.Errorf("accept media stream %d: %w", i, err)
		}
		frameStreams[i] = frameStream
	}
	defer closeFrameStreams(frameStreams)

	expectedSequence := uint64(1)
	pendingFrames := make(map[uint64]transport.FrameReadResult)

	for result := range transport.ReadFramesFromStreams(ctx, frameStreams) {
		if result.Err != nil {
			if errors.Is(result.Err, io.EOF) || transport.IsGracefulRemoteClose(result.Err) {
				log.Printf("media stream finished")
				return nil
			}
			return fmt.Errorf("read frame from media stream %d: %w", result.StreamIndex, result.Err)
		}

		if result.Frame.Sequence < expectedSequence {
			action, err := handleReceivedFrame(result, validator, policy, options.OnAcceptedPayload)
			if err != nil {
				return err
			}
			if err := handlePolicyAction(action); err != nil {
				return err
			}
			continue
		}

		if _, exists := pendingFrames[result.Frame.Sequence]; exists {
			log.Printf("frame dropped: sequence=%d media_stream=%d reason=duplicate pending sequence",
				result.Frame.Sequence,
				result.StreamIndex,
			)
			continue
		}

		if len(pendingFrames) >= maxReorderBufferFrames {
			return fmt.Errorf("%w: reorder buffer overflow", ErrValidateFrame)
		}

		pendingFrames[result.Frame.Sequence] = result

		for {
			next, ok := pendingFrames[expectedSequence]
			if !ok {
				break
			}
			delete(pendingFrames, expectedSequence)

			action, err := handleReceivedFrame(next, validator, policy, options.OnAcceptedPayload)
			if err != nil {
				return err
			}
			if err := handlePolicyAction(action); err != nil {
				return err
			}
			expectedSequence++
		}
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("receive frames: %w", err)
	}
	return nil
}

func handleReceivedFrame(result transport.FrameReadResult, validator *FrameValidator, policy *FramePolicy, onAcceptedPayload func([]byte) error) (FramePolicyAction, error) {
	err := validator.ValidateFrame(result.Frame)
	signatureInvalid := errors.Is(err, ErrInvalidFrameSignature)
	action := policy.RecordFrame(signatureInvalid, time.Now())
	sequence := uint64(0)
	payloadBytes := 0
	if result.Frame != nil {
		sequence = result.Frame.Sequence
		payloadBytes = len(result.Frame.Payload)
	}

	if err != nil {
		log.Printf("frame dropped: sequence=%d media_stream=%d reason=%v", sequence, result.StreamIndex, err)
		return action, nil
	}

	if onAcceptedPayload != nil {
		if err := onAcceptedPayload(result.Frame.Payload); err != nil {
			return action, fmt.Errorf("handle accepted payload: %w", err)
		}
	}

	log.Printf("frame accepted: sequence=%d media_stream=%d payload_bytes=%d",
		sequence,
		result.StreamIndex,
		payloadBytes,
	)

	return action, nil
}

func handlePolicyAction(action FramePolicyAction) error {
	switch action {
	case FramePolicyActionRehandshake:
		return ErrRehandshakeRequired
	case FramePolicyActionDropConnection:
		return ErrUntrustedConnection
	default:
		return nil
	}
}

func closeFrameStreams(streams []*quic.Stream) {
	for _, stream := range streams {
		if stream != nil {
			_ = stream.Close()
		}
	}
}
