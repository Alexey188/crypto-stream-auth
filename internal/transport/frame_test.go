package transport

import (
	"bytes"
	"crypto-stream-auth/internal/domain"
	"errors"
	"testing"
	"time"
)

func TestFrameTransportRoundTrip(t *testing.T) {
	frame := testFrame()

	data, err := EncodeFrame(frame)
	if err != nil {
		t.Fatalf("EncodeFrame() error = %v", err)
	}

	decoded, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("DecodeFrame() error = %v", err)
	}

	if decoded.SessionID != frame.SessionID {
		t.Fatalf("session id mismatch")
	}
	if decoded.Sequence != frame.Sequence {
		t.Fatalf("sequence = %d, want %d", decoded.Sequence, frame.Sequence)
	}
	if decoded.Timestamp != frame.Timestamp {
		t.Fatalf("timestamp = %d, want %d", decoded.Timestamp, frame.Timestamp)
	}
	if !bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatalf("payload mismatch")
	}
	if decoded.Signature != frame.Signature {
		t.Fatalf("signature mismatch")
	}
}

func TestFrameTransportAnomalies(t *testing.T) {
	t.Run("rejects_empty_payload", func(t *testing.T) {
		frame := testFrame()
		frame.Payload = nil

		_, err := EncodeFrame(frame)
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("EncodeFrame() error = %v, want %v", err, ErrTransport)
		}
	})

	t.Run("rejects_trailing_bytes", func(t *testing.T) {
		data, err := EncodeFrame(testFrame())
		if err != nil {
			t.Fatalf("EncodeFrame() error = %v", err)
		}
		data = append(data, 0)

		_, err = DecodeFrame(data)
		if !errors.Is(err, ErrTransport) {
			t.Fatalf("DecodeFrame() error = %v, want %v", err, ErrTransport)
		}
	})
}

func testFrame() *domain.VideoFrame {
	var sessionID [16]byte
	sessionID[0] = 1

	var signature [64]byte
	signature[0] = 1

	return &domain.VideoFrame{
		SessionID: sessionID,
		Sequence:  1,
		Timestamp: time.Now().Unix(),
		Payload:   []byte("nalu"),
		Signature: signature,
	}
}
