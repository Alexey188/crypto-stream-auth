package handshake

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"time"
)

type ProducerSession struct {
	SessionID           [SessionIDSize]byte
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
		EphemeralPrivateKey: append(ed25519.PrivateKey(nil), ephemeralPrivateKey...),
		HandshakeTime:       now,
	}

	return response, session, nil
}

func VerifyResponse(response *Response, rootCA *x509.Certificate, request *Request, maxAge time.Duration) (*ConsumerSession, error) {
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
	if err := VerifyHandshake(payload, rootCA, request.ConsumerNonce, maxAge); err != nil {
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
