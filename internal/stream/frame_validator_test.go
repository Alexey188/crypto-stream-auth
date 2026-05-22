package stream

import (
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto-stream-auth/internal/domain"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestFrameValidationRoundTrip(t *testing.T) {
	publicKey, privateKey := newEd25519Keys(t)
	sessionID := testStreamSessionID()
	validator := newFrameValidator(t, sessionID, publicKey)

	frame := signedFrame(t, privateKey, sessionID, 1, time.Now())
	if err := validator.ValidateFrame(frame); err != nil {
		t.Fatalf("ValidateFrame() error = %v", err)
	}
}

func TestFrameValidationAnomalies(t *testing.T) {
	t.Run("rejects_replay_sequence", func(t *testing.T) {
		publicKey, privateKey := newEd25519Keys(t)
		sessionID := testStreamSessionID()
		validator := newFrameValidator(t, sessionID, publicKey)

		if err := validator.ValidateFrame(signedFrame(t, privateKey, sessionID, 1, time.Now())); err != nil {
			t.Fatalf("ValidateFrame() error = %v", err)
		}

		err := validator.ValidateFrame(signedFrame(t, privateKey, sessionID, 1, time.Now()))
		if !errors.Is(err, ErrValidateFrame) {
			t.Fatalf("ValidateFrame() error = %v, want %v", err, ErrValidateFrame)
		}
	})

	t.Run("rejects_wrong_session_id", func(t *testing.T) {
		publicKey, privateKey := newEd25519Keys(t)
		sessionID := testStreamSessionID()
		validator := newFrameValidator(t, sessionID, publicKey)

		wrongSessionID := sessionID
		wrongSessionID[1] = 1

		err := validator.ValidateFrame(signedFrame(t, privateKey, wrongSessionID, 1, time.Now()))
		if !errors.Is(err, ErrValidateFrame) {
			t.Fatalf("ValidateFrame() error = %v, want %v", err, ErrValidateFrame)
		}
	})

	t.Run("rejects_expired_timestamp", func(t *testing.T) {
		publicKey, privateKey := newEd25519Keys(t)
		sessionID := testStreamSessionID()
		validator := newFrameValidator(t, sessionID, publicKey)

		err := validator.ValidateFrame(signedFrame(t, privateKey, sessionID, 1, time.Now().Add(-2*time.Minute)))
		if !errors.Is(err, ErrValidateFrame) {
			t.Fatalf("ValidateFrame() error = %v, want %v", err, ErrValidateFrame)
		}
	})

	t.Run("rejects_bad_signature", func(t *testing.T) {
		publicKey, privateKey := newEd25519Keys(t)
		sessionID := testStreamSessionID()
		validator := newFrameValidator(t, sessionID, publicKey)

		frame := signedFrame(t, privateKey, sessionID, 1, time.Now())
		frame.Payload[0] ^= 1

		err := validator.ValidateFrame(frame)
		if !errors.Is(err, ErrInvalidFrameSignature) {
			t.Fatalf("ValidateFrame() error = %v, want %v", err, ErrInvalidFrameSignature)
		}
	})

	t.Run("rejects_empty_payload", func(t *testing.T) {
		publicKey, privateKey := newEd25519Keys(t)
		sessionID := testStreamSessionID()
		validator := newFrameValidator(t, sessionID, publicKey)

		frame := signedFrame(t, privateKey, sessionID, 1, time.Now())
		frame.Payload = nil

		err := validator.ValidateFrame(frame)
		if !errors.Is(err, ErrValidateFrame) {
			t.Fatalf("ValidateFrame() error = %v, want %v", err, ErrValidateFrame)
		}
	})
}

func newEd25519Keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	return publicKey, privateKey
}

func newFrameValidator(t *testing.T, sessionID [16]byte, publicKey ed25519.PublicKey) *FrameValidator {
	t.Helper()

	validator, err := NewFrameValidator(sessionID, publicKey, time.Minute)
	if err != nil {
		t.Fatalf("NewFrameValidator() error = %v", err)
	}

	return validator
}

func signedFrame(t *testing.T, privateKey ed25519.PrivateKey, sessionID [16]byte, sequence uint64, timestamp time.Time) *domain.VideoFrame {
	t.Helper()

	frame := &domain.VideoFrame{
		SessionID: sessionID,
		Sequence:  sequence,
		Timestamp: timestamp.Unix(),
		Payload:   []byte("nalu"),
	}

	if err := authcrypto.SignFrameSignature(privateKey, frame); err != nil {
		t.Fatalf("SignFrameSignature() error = %v", err)
	}

	return frame
}

func testStreamSessionID() [16]byte {
	var sessionID [16]byte
	sessionID[0] = 1
	return sessionID
}
