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

var (
	ErrRehandshakeRequired = errors.New("rehandshake required")
	ErrUntrustedConnection = errors.New("untrusted connection")
)

type ReceiveOptions struct {
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

	validator, err := NewFrameValidator(session.SessionID, session.EphemeralPublicKey)
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

	statsWindowStarted := time.Now()
	var statsAccepted uint64
	var statsDropped uint64
	var statsBadSignatures uint64
	var statsPayloadBytes uint64

	for result := range transport.ReadFramesFromStreams(ctx, frameStreams) {
		if result.Err != nil {
			if errors.Is(result.Err, io.EOF) || transport.IsGracefulRemoteClose(result.Err) {
				log.Printf("media stream finished")
				return nil
			}
			return fmt.Errorf("read frame from media stream %d: %w", result.StreamIndex, result.Err)
		}

		action, dropped, badSignature, payloadBytes, err := handleReceivedFrame(result, validator, policy, options.OnAcceptedPayload)
		if err != nil {
			return err
		}

		if dropped {
			statsDropped++
			if badSignature {
				statsBadSignatures++
			}
		} else {
			statsAccepted++
			statsPayloadBytes += uint64(payloadBytes)
		}

		now := time.Now()
		if now.Sub(statsWindowStarted) >= time.Second {
			elapsed := now.Sub(statsWindowStarted).Seconds()
			avgPayload := uint64(0)
			if statsAccepted > 0 {
				avgPayload = statsPayloadBytes / statsAccepted
			}
			log.Printf("consumer stats: accepted=%d dropped=%d bad_signatures=%d bytes=%d fps=%.1f avg_payload=%d",
				statsAccepted,
				statsDropped,
				statsBadSignatures,
				statsPayloadBytes,
				float64(statsAccepted)/elapsed,
				avgPayload,
			)

			statsWindowStarted = now
			statsAccepted = 0
			statsDropped = 0
			statsBadSignatures = 0
			statsPayloadBytes = 0
		}

		if err := handlePolicyAction(action); err != nil {
			return err
		}
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("receive frames: %w", err)
	}
	return nil
}

func handleReceivedFrame(result transport.FrameReadResult, validator *FrameValidator, policy *FramePolicy, onAcceptedPayload func([]byte) error) (FramePolicyAction, bool, bool, int, error) {
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
		return action, true, signatureInvalid, 0, nil
	}

	if onAcceptedPayload != nil {
		if err := onAcceptedPayload(result.Frame.Payload); err != nil {
			return action, false, false, payloadBytes, fmt.Errorf("handle accepted payload: %w", err)
		}
	}

	return action, false, false, payloadBytes, nil
}

func handlePolicyAction(action FramePolicyAction) error {
	switch action {
	case FramePolicyActionRehandshake:
		return ErrRehandshakeRequired
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
