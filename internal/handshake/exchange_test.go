package handshake

import (
	stdcrypto "crypto"
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

type testRSAPSSSigner struct {
	privateKey *rsa.PrivateKey
}

func (s testRSAPSSSigner) SignPSS(digest []byte) ([]byte, error) {
	return rsa.SignPSS(rand.Reader, s.privateKey, stdcrypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       stdcrypto.SHA256,
	})
}

func TestHandshakeExchangeRoundTrip(t *testing.T) {
	rootCA, cameraPrivateKey, cameraCertificate := newTestCameraIdentity(t)
	request, err := NewRequest()
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	response, producerSession, err := BuildResponse(request, cameraCertificate, testRSAPSSSigner{privateKey: cameraPrivateKey})
	if err != nil {
		t.Fatalf("BuildResponse() error = %v", err)
	}

	consumerSession, err := VerifyResponse(response, rootCA.Certificate, request, time.Minute)
	if err != nil {
		t.Fatalf("VerifyResponse() error = %v", err)
	}

	if consumerSession.SessionID != producerSession.SessionID {
		t.Fatalf("session id mismatch")
	}
	if len(producerSession.EphemeralPrivateKey) == 0 {
		t.Fatalf("producer ephemeral private key is empty")
	}
	if len(consumerSession.EphemeralPublicKey) == 0 {
		t.Fatalf("consumer ephemeral public key is empty")
	}
}

func TestHandshakeExchangeAnomalies(t *testing.T) {
	t.Run("rejects_nonce_mismatch", func(t *testing.T) {
		rootCA, cameraPrivateKey, cameraCertificate := newTestCameraIdentity(t)
		request, response := newSignedResponse(t, cameraCertificate, cameraPrivateKey)

		wrongRequest := *request
		wrongRequest.ConsumerNonce[0] ^= 1

		_, err := VerifyResponse(response, rootCA.Certificate, &wrongRequest, time.Minute)
		if !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("VerifyResponse() error = %v, want %v", err, ErrInvalidHandshake)
		}
	})

	t.Run("rejects_tampered_handshake_signature", func(t *testing.T) {
		rootCA, cameraPrivateKey, cameraCertificate := newTestCameraIdentity(t)
		request, response := newSignedResponse(t, cameraCertificate, cameraPrivateKey)

		response.Signature[0] ^= 1

		_, err := VerifyResponse(response, rootCA.Certificate, request, time.Minute)
		if !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("VerifyResponse() error = %v, want %v", err, ErrInvalidHandshake)
		}
	})

	t.Run("rejects_expired_timestamp", func(t *testing.T) {
		rootCA, cameraPrivateKey, cameraCertificate := newTestCameraIdentity(t)
		request, err := NewRequest()
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}

		payload, _, err := GenerateHandshake(
			cameraCertificate,
			testRSAPSSSigner{privateKey: cameraPrivateKey},
			testSessionID(),
			request.ConsumerNonce,
			time.Now().Add(-2*time.Minute).Unix(),
		)
		if err != nil {
			t.Fatalf("GenerateHandshake() error = %v", err)
		}

		_, err = VerifyResponse(responseFromPayload(payload), rootCA.Certificate, request, time.Second)
		if !errors.Is(err, ErrInvalidHandshake) {
			t.Fatalf("VerifyResponse() error = %v, want %v", err, ErrInvalidHandshake)
		}
	})
}

func newTestCameraIdentity(t *testing.T) (*authcrypto.RootCA, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	rootCA, err := authcrypto.GenerateRootCA("Test Root")
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}

	cameraPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	cameraCertificate, err := authcrypto.IssueCameraCertificate(rootCA, "cam-test", &cameraPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("IssueCameraCertificate() error = %v", err)
	}

	return rootCA, cameraPrivateKey, cameraCertificate
}

func newSignedResponse(t *testing.T, cameraCertificate *x509.Certificate, cameraPrivateKey *rsa.PrivateKey) (*Request, *Response) {
	t.Helper()

	request, err := NewRequest()
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	response, _, err := BuildResponse(request, cameraCertificate, testRSAPSSSigner{privateKey: cameraPrivateKey})
	if err != nil {
		t.Fatalf("BuildResponse() error = %v", err)
	}

	return request, response
}
