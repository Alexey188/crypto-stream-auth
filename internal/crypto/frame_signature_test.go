package crypto

import (
	"crypto-stream-auth/internal/domain"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestFrameSignature(t *testing.T) {
	t.Run("accepts_valid_signature", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}

		frame := testVideoFrame()
		if err := SignFrameSignature(privateKey, frame); err != nil {
			t.Fatalf("SignFrameSignature() error = %v", err)
		}

		ok, err := VerifyFrameSignature(publicKey, frame)
		if err != nil {
			t.Fatalf("VerifyFrameSignature() error = %v", err)
		}
		if !ok {
			t.Fatalf("VerifyFrameSignature() ok = false, want true")
		}
	})

	t.Run("rejects_tampered_payload", func(t *testing.T) {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey() error = %v", err)
		}

		frame := testVideoFrame()
		if err := SignFrameSignature(privateKey, frame); err != nil {
			t.Fatalf("SignFrameSignature() error = %v", err)
		}
		frame.Payload[0] ^= 1

		ok, err := VerifyFrameSignature(publicKey, frame)
		if !errors.Is(err, ErrFrameSignature) {
			t.Fatalf("VerifyFrameSignature() error = %v, want %v", err, ErrFrameSignature)
		}
		if ok {
			t.Fatalf("VerifyFrameSignature() ok = true, want false")
		}
	})
}

func testVideoFrame() *domain.VideoFrame {
	var sessionID [16]byte
	sessionID[0] = 1

	return &domain.VideoFrame{
		SessionID: sessionID,
		Sequence:  1,
		Timestamp: time.Now().Unix(),
		Payload:   []byte("nalu"),
	}
}
