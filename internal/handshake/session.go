package handshake

import (
	stdcrypto "crypto"
	authcrypto "crypto-stream-auth/internal/crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidHandshake = errors.New("invalid handshake")

// RSAPSSSigner подписывает хэш через долговременный ключ камеры.
type RSAPSSSigner interface {
	SignPSS(digest []byte) ([]byte, error)
}

type CameraCertificateVerifier interface {
	VerifyCameraCertificate(cameraCertificate *x509.Certificate) (*rsa.PublicKey, error)
}

type rootCAVerifier struct {
	rootCA *x509.Certificate
}

func (verifier rootCAVerifier) VerifyCameraCertificate(cameraCertificate *x509.Certificate) (*rsa.PublicKey, error) {
	return authcrypto.VerifyCameraCertificate(cameraCertificate, verifier.rootCA)
}

type HandshakePayload struct {
	CameraCertificate  *x509.Certificate
	EphemeralPublicKey ed25519.PublicKey
	SessionID          [SessionIDSize]byte
	ConsumerNonce      [NonceSize]byte
	Timestamp          int64
	Signature          []byte
}

func BuildHandshakeMessage(sessionID [SessionIDSize]byte, nonce [NonceSize]byte, timestamp int64, ephemeralPublicKey ed25519.PublicKey) ([]byte, error) {
	if len(ephemeralPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid ephemeral public key size", ErrInvalidHandshake)
	}

	message := make([]byte, 0, SessionIDSize+NonceSize+timestampSize+ed25519.PublicKeySize)
	message = append(message, sessionID[:]...)
	message = append(message, nonce[:]...)
	message = binary.BigEndian.AppendUint64(message, uint64(timestamp))
	message = append(message, ephemeralPublicKey...)

	return message, nil
}

func GenerateHandshake(cameraCertificate *x509.Certificate, signer RSAPSSSigner, sessionID [SessionIDSize]byte,
	nonce [NonceSize]byte, timestamp int64) (*HandshakePayload, ed25519.PrivateKey, error) {

	ephemeralPublicKey, ephemeralPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generate ephemeral keys: %w", ErrInvalidHandshake, err)
	}

	payload, err := SignHandshake(cameraCertificate, signer, sessionID, nonce, timestamp, ephemeralPublicKey)
	if err != nil {
		return nil, nil, err
	}

	return payload, ephemeralPrivateKey, nil
}

func SignHandshake(cameraCertificate *x509.Certificate, signer RSAPSSSigner, sessionID [SessionIDSize]byte,
	nonce [NonceSize]byte, timestamp int64, ephemeralPublicKey ed25519.PublicKey) (*HandshakePayload, error) {

	if cameraCertificate == nil {
		return nil, fmt.Errorf("%w: camera certificate is nil", ErrInvalidHandshake)
	}
	if signer == nil {
		return nil, fmt.Errorf("%w: signer is nil", ErrInvalidHandshake)
	}

	digest, err := buildHandshakeDigest(sessionID, nonce, timestamp, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}

	signature, err := signer.SignPSS(digest[:])
	if err != nil {
		return nil, fmt.Errorf("%w: sign handshake: %w", ErrInvalidHandshake, err)
	}

	return &HandshakePayload{
		CameraCertificate:  cameraCertificate,
		EphemeralPublicKey: ephemeralPublicKey,
		SessionID:          sessionID,
		ConsumerNonce:      nonce,
		Timestamp:          timestamp,
		Signature:          signature,
	}, nil
}

func VerifyHandshake(payload *HandshakePayload, rootCA *x509.Certificate, consumerNonce [NonceSize]byte, maxHandshakeAge time.Duration) error {
	return verifyHandshake(payload, rootCAVerifier{rootCA: rootCA}, consumerNonce, maxHandshakeAge)
}

func VerifyHandshakeWithTrustStore(payload *HandshakePayload, trustStore *authcrypto.TrustStore, consumerNonce [NonceSize]byte, maxHandshakeAge time.Duration) error {
	return verifyHandshake(payload, trustStore, consumerNonce, maxHandshakeAge)
}

func verifyHandshake(payload *HandshakePayload, verifier CameraCertificateVerifier, consumerNonce [NonceSize]byte, maxHandshakeAge time.Duration) error {
	if payload == nil {
		return fmt.Errorf("%w: payload is nil", ErrInvalidHandshake)
	}
	if verifier == nil {
		return fmt.Errorf("%w: certificate verifier is nil", ErrInvalidHandshake)
	}
	if payload.ConsumerNonce != consumerNonce {
		return fmt.Errorf("%w: consumer nonce mismatch", ErrInvalidHandshake)
	}
	if maxHandshakeAge <= 0 {
		return fmt.Errorf("%w: max handshake age must be positive", ErrInvalidHandshake)
	}

	timestamp := time.Unix(payload.Timestamp, 0)
	age := time.Since(timestamp)
	if age < 0 {
		return fmt.Errorf("%w: timestamp is from future", ErrInvalidHandshake)
	}
	if age > maxHandshakeAge {
		return fmt.Errorf("%w: timestamp is expired", ErrInvalidHandshake)
	}

	cameraPublicKey, err := verifier.VerifyCameraCertificate(payload.CameraCertificate)
	if err != nil {
		return fmt.Errorf("%w: verify camera certificate: %w", ErrInvalidHandshake, err)
	}

	digest, err := buildHandshakeDigest(payload.SessionID, payload.ConsumerNonce, payload.Timestamp, payload.EphemeralPublicKey)
	if err != nil {
		return err
	}

	err = rsa.VerifyPSS(
		cameraPublicKey,
		stdcrypto.SHA256,
		digest[:],
		payload.Signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       stdcrypto.SHA256,
		},
	)
	if err != nil {
		return fmt.Errorf("%w: invalid handshake signature: %w", ErrInvalidHandshake, err)
	}

	return nil
}

func buildHandshakeDigest(sessionID [SessionIDSize]byte, nonce [NonceSize]byte, timestamp int64, ephemeralPublicKey ed25519.PublicKey) ([sha256.Size]byte, error) {
	message, err := BuildHandshakeMessage(sessionID, nonce, timestamp, ephemeralPublicKey)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: build message: %w", ErrInvalidHandshake, err)
	}

	return sha256.Sum256(message), nil
}
