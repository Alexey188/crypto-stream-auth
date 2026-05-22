package stream

import (
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/domain"
	"crypto/ed25519"
	"errors"
	"fmt"
)

var (
	ErrValidateFrame         = errors.New("validate frame")
	ErrInvalidFrameSignature = errors.New("invalid frame signature")
)

type FrameValidator struct {
	sessionID       domain.SessionID
	publicKey       ed25519.PublicKey
	lastSequence    uint64
	hasLastSequence bool
}

func NewFrameValidator(sessionID domain.SessionID, publicKey ed25519.PublicKey) (*FrameValidator, error) {
	if sessionID == (domain.SessionID{}) {
		return nil, fmt.Errorf("%w: session id is empty", ErrValidateFrame)
	}
	if publicKey == nil {
		return nil, fmt.Errorf("%w: public key is nil", ErrValidateFrame)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key invalid size", ErrValidateFrame)
	}

	return &FrameValidator{
		sessionID: sessionID,
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
	}, nil
}

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
	if frame.Timestamp <= 0 {
		return fmt.Errorf("%w: frame timestamp is invalid", ErrValidateFrame)
	}

	if err := authcrypto.VerifyFrameSignature(validator.publicKey, frame); err != nil {
		return fmt.Errorf("%w: verify signature: %w", ErrInvalidFrameSignature, err)
	}

	validator.lastSequence = frame.Sequence
	validator.hasLastSequence = true
	return nil
}
