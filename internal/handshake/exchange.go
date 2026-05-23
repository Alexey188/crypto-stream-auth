package handshake

import (
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"time"
)

type ProducerSession struct {
	SessionID           [SessionIDSize]byte
	EphemeralPublicKey  ed25519.PublicKey
	EphemeralPrivateKey ed25519.PrivateKey
	HandshakeTime       time.Time
}

type ConsumerSession struct {
	SessionID          [SessionIDSize]byte
	EphemeralPublicKey ed25519.PublicKey
	CameraCertificate  *x509.Certificate
	HandshakeTime      time.Time
}

func NewRequest() (*Request, error) {
	request := &Request{ProtocolVersion: ProtocolVersion}
	if err := fillRandomNonZero(request.ConsumerNonce[:]); err != nil {
		return nil, fmt.Errorf("%w: generate consumer nonce: %w", ErrInvalidHandshake, err)
	}

	return request, nil
}

func BuildResponse(request *Request, cameraCertificate *x509.Certificate, signer RSAPSSSigner) (*Response, *ProducerSession, error) {
	if err := validateRequest(request); err != nil {
		return nil, nil, err
	}

	var sessionID [SessionIDSize]byte
	if err := fillRandomNonZero(sessionID[:]); err != nil {
		return nil, nil, fmt.Errorf("%w: generate session id: %w", ErrInvalidHandshake, err)
	}

	now := time.Now()
	payload, ephemeralPrivateKey, err := GenerateHandshake(
		cameraCertificate,
		signer,
		sessionID,
		request.ConsumerNonce,
		now.Unix(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generate handshake: %w", ErrInvalidHandshake, err)
	}

	response := responseFromPayload(payload)
	if err := validateResponse(response); err != nil {
		return nil, nil, err
	}

	session := &ProducerSession{
		SessionID:           sessionID,
		EphemeralPublicKey:  append(ed25519.PublicKey(nil), payload.EphemeralPublicKey...),
		EphemeralPrivateKey: append(ed25519.PrivateKey(nil), ephemeralPrivateKey...),
		HandshakeTime:       now,
	}

	return response, session, nil
}

func BuildResponseForSession(request *Request, cameraCertificate *x509.Certificate, signer RSAPSSSigner, session *ProducerSession) (*Response, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("%w: producer session is nil", ErrInvalidHandshake)
	}
	if session.SessionID == [SessionIDSize]byte{} {
		return nil, fmt.Errorf("%w: session id is empty", ErrInvalidHandshake)
	}
	if len(session.EphemeralPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: ephemeral public key size is invalid", ErrInvalidHandshake)
	}

	now := time.Now()
	payload, err := SignHandshake(
		cameraCertificate,
		signer,
		session.SessionID,
		request.ConsumerNonce,
		now.Unix(),
		session.EphemeralPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: sign existing session handshake: %w", ErrInvalidHandshake, err)
	}

	response := responseFromPayload(payload)
	if err := validateResponse(response); err != nil {
		return nil, err
	}

	return response, nil
}

func VerifyResponse(response *Response, rootCA *x509.Certificate, request *Request, maxAge time.Duration) (*ConsumerSession, error) {
	return verifyResponse(response, rootCAVerifier{rootCA: rootCA}, request, maxAge)
}

func VerifyResponseWithTrustStore(response *Response, trustStore *authcrypto.TrustStore, request *Request, maxAge time.Duration) (*ConsumerSession, error) {
	return verifyResponse(response, trustStore, request, maxAge)
}

func verifyResponse(response *Response, verifier CameraCertificateVerifier, request *Request, maxAge time.Duration) (*ConsumerSession, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if err := validateResponse(response); err != nil {
		return nil, err
	}

	cameraCertificate, err := x509.ParseCertificate(response.CameraCertificateDER)
	if err != nil {
		return nil, fmt.Errorf("%w: parse camera certificate: %w", ErrInvalidHandshake, err)
	}

	payload := payloadFromResponse(response, cameraCertificate)
	if err := verifyHandshake(payload, verifier, request.ConsumerNonce, maxAge); err != nil {
		return nil, fmt.Errorf("%w: verify handshake: %w", ErrInvalidHandshake, err)
	}

	return &ConsumerSession{
		SessionID:          response.SessionID,
		EphemeralPublicKey: append(ed25519.PublicKey(nil), response.EphemeralPublicKey...),
		CameraCertificate:  cameraCertificate,
		HandshakeTime:      time.Unix(response.Timestamp, 0),
	}, nil
}

func responseFromPayload(payload *HandshakePayload) *Response {
	return &Response{
		CameraCertificateDER: append([]byte(nil), payload.CameraCertificate.Raw...),
		EphemeralPublicKey:   append(ed25519.PublicKey(nil), payload.EphemeralPublicKey...),
		SessionID:            payload.SessionID,
		ConsumerNonce:        payload.ConsumerNonce,
		Timestamp:            payload.Timestamp,
		Signature:            append([]byte(nil), payload.Signature...),
	}
}

func payloadFromResponse(response *Response, cameraCertificate *x509.Certificate) *HandshakePayload {
	return &HandshakePayload{
		CameraCertificate:  cameraCertificate,
		EphemeralPublicKey: response.EphemeralPublicKey,
		SessionID:          response.SessionID,
		ConsumerNonce:      response.ConsumerNonce,
		Timestamp:          response.Timestamp,
		Signature:          response.Signature,
	}
}

func fillRandomNonZero(dst []byte) error {
	for {
		if _, err := io.ReadFull(rand.Reader, dst); err != nil {
			return err
		}
		for _, b := range dst {
			if b != 0 {
				return nil
			}
		}
	}
}
