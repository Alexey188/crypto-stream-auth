package stream

import (
	"crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/domain"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

var (
	ErrValidateFrame         = errors.New("validate frame")
	ErrInvalidFrameSignature = errors.New("invalid frame signature")
)

type FrameValidator struct {
	sessionID       [16]byte
	publicKey       ed25519.PublicKey
	lastSequence    uint64
	hasLastSequence bool
	maxFrameAge     time.Duration
}

func NewFrameValidator(sessionID [16]byte, publicKey ed25519.PublicKey, maxFrameAge time.Duration) (*FrameValidator, error) {
	if sessionID == [16]byte{} {
		return nil, fmt.Errorf("%w: session id is empty", ErrValidateFrame)
	}
	if publicKey == nil {
		return nil, fmt.Errorf("%w: public key is nil", ErrValidateFrame)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key invalid size", ErrValidateFrame)
	}
	if maxFrameAge <= 0 {
		return nil, fmt.Errorf("%w: max frame age must be positive", ErrValidateFrame)
	}

	return &FrameValidator{
		sessionID:    sessionID,
		publicKey:    publicKey,
		lastSequence: 0,
		maxFrameAge:  maxFrameAge,
	}, nil
}

// проверка кадра
func (validator *FrameValidator) ValidateFrame(frame *domain.VideoFrame) error {

	if validator == nil {
		return fmt.Errorf("%w: validator is nil", ErrValidateFrame)
	}

	if frame == nil {
		return fmt.Errorf("%w: frame is nil", ErrValidateFrame)
	}

	if frame.SessionID != validator.sessionID {
		return fmt.Errorf("%w: session id mismatch", ErrValidateFrame)
	}

	if len(frame.Payload) == 0 {
		return fmt.Errorf("%w: frame payload is empty", ErrValidateFrame)
	}

	if len(frame.Payload) > domain.MaxFramePayloadSize {
		return fmt.Errorf("%w: frame payload is too large", ErrValidateFrame)
	}

	if frame.Sequence == 0 {
		return fmt.Errorf("%w: frame sequence is empty", ErrValidateFrame)
	}

	if validator.hasLastSequence && frame.Sequence <= validator.lastSequence {
		return fmt.Errorf("%w: replay or old frame", ErrValidateFrame)
	}

	ts := time.Unix(frame.Timestamp, 0)
	age := time.Since(ts)

	if age < 0 {
		return fmt.Errorf("%w: frame timestamp is from future", ErrValidateFrame)
	}

	if age > validator.maxFrameAge {
		return fmt.Errorf("%w: frame is expired", ErrValidateFrame)
	}
	ok, err := crypto.VerifyFrameSignature(validator.publicKey, frame)
	if err != nil {
		return fmt.Errorf("%w: verify signature: %w", ErrInvalidFrameSignature, err)
	}
	if !ok {
		return fmt.Errorf("%w: invalid signature", ErrInvalidFrameSignature)

	}

	validator.lastSequence = frame.Sequence
	validator.hasLastSequence = true
	return nil
}
