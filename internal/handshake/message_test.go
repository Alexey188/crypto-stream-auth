package handshake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestHandshakeMessageRoundTrip(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		request := &Request{
			ProtocolVersion: ProtocolVersion,
			ConsumerNonce:   testNonce(),
		}

		data, err := EncodeRequest(request)
		if err != nil {
			t.Fatalf("EncodeRequest() error = %v", err)
		}

		decoded, err := DecodeRequest(data)
		if err != nil {
			t.Fatalf("DecodeRequest() error = %v", err)
		}

		if decoded.ProtocolVersion != request.ProtocolVersion {
			t.Fatalf("protocol version = %d, want %d", decoded.ProtocolVersion, request.ProtocolVersion)
		}
		if decoded.ConsumerNonce != request.ConsumerNonce {
			t.Fatalf("consumer nonce mismatch")
		}
	})

	t.Run("response", func(t *testing.T) {
		response := testResponse(t)

		data, err := EncodeResponse(response)
		if err != nil {
			t.Fatalf("EncodeResponse() error = %v", err)
		}

		decoded, err := DecodeResponse(data)
		if err != nil {
			t.Fatalf("DecodeResponse() error = %v", err)
		}

		if !bytes.Equal(decoded.CameraCertificateDER, response.CameraCertificateDER) {
			t.Fatalf("camera certificate mismatch")
		}
		if !bytes.Equal(decoded.EphemeralPublicKey, response.EphemeralPublicKey) {
			t.Fatalf("ephemeral public key mismatch")
		}
		if decoded.SessionID != response.SessionID {
			t.Fatalf("session id mismatch")
		}
		if decoded.ConsumerNonce != response.ConsumerNonce {
			t.Fatalf("consumer nonce mismatch")
		}
		if decoded.Timestamp != response.Timestamp {
			t.Fatalf("timestamp = %d, want %d", decoded.Timestamp, response.Timestamp)
		}
		if !bytes.Equal(decoded.Signature, response.Signature) {
			t.Fatalf("signature mismatch")
		}
	})
}

func TestHandshakeMessageAnomalies(t *testing.T) {
	t.Run("rejects_invalid_protocol_version", func(t *testing.T) {
		data := []byte{ProtocolVersion + 1}
		nonce := testNonce()
		data = append(data, nonce[:]...)

		_, err := DecodeRequest(data)
		if !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("DecodeRequest() error = %v, want %v", err, ErrInvalidHandshake)
		}
	})

	t.Run("rejects_empty_consumer_nonce", func(t *testing.T) {
		_, err := EncodeRequest(&Request{ProtocolVersion: ProtocolVersion})
		if !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("EncodeRequest() error = %v, want %v", err, ErrInvalidHandshake)
		}
	})

	t.Run("rejects_trailing_bytes_in_response", func(t *testing.T) {
		data, err := EncodeResponse(testResponse(t))
		if err != nil {
			t.Fatalf("EncodeResponse() error = %v", err)
		}
		data = append(data, 0)

		_, err = DecodeResponse(data)
		if !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("DecodeResponse() error = %v, want %v", err, ErrInvalidHandshake)
		}
	})
}

func testResponse(t *testing.T) *Response {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	return &Response{
		CameraCertificateDER: []byte{1, 2, 3},
		EphemeralPublicKey:   publicKey,
		SessionID:            testSessionID(),
		ConsumerNonce:        testNonce(),
		Timestamp:            1,
		Signature:            bytes.Repeat([]byte{1}, RSAPSSSignatureSize),
	}
}

func testNonce() [NonceSize]byte {
	var nonce [NonceSize]byte
	nonce[0] = 1
	return nonce
}

func testSessionID() [SessionIDSize]byte {
	var sessionID [SessionIDSize]byte
	sessionID[0] = 1
	return sessionID
}
