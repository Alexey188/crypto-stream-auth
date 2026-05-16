package crypto

import (
	stdcrypto "crypto"
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

var (
	ErrInvalidHandshake = errors.New("invalid handshake")
)

// интерфейс для подписания handshake
type RSAPSSSigner interface {
	SignPSS(digest []byte) ([]byte, error)
}

// HandshakePayload — это пакет данных, который Камера отправляет Клиенту при подключении.
type HandshakePayload struct {
	CameraCertificate  *x509.Certificate
	EphemeralPublicKey ed25519.PublicKey
	SessionID          [16]byte
	ConsumerNonce      [16]byte
	Timestamp          int64
	Signature          []byte
}

func BuildHandshakeMessage(sessionID [16]byte, nonce [16]byte, timestamp int64, ephemeralPublicKey ed25519.PublicKey) ([]byte, error) {
	if len(ephemeralPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid ephemeral public key size", ErrInvalidHandshake)
	}

	buf := make([]byte, 0, 16+16+8+ed25519.PublicKeySize)
	buf = append(buf, sessionID[:]...)
	buf = append(buf, nonce[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(timestamp))
	buf = append(buf, ephemeralPublicKey...)

	return buf, nil
}

// GenerateHandshake вызывается на стороне Камеры перед началом трансляции.
func GenerateHandshake(camCert *x509.Certificate, signer RSAPSSSigner, sessionID [16]byte,
	nonce [16]byte, timestamp int64) (*HandshakePayload, ed25519.PrivateKey, error) {

	if camCert == nil {
		return nil, nil, fmt.Errorf("%w: camera certificate is nil", ErrInvalidHandshake)
	}
	if signer == nil {
		return nil, nil, fmt.Errorf("%w: signer is nil", ErrInvalidHandshake)
	}
	ephemeralPublicKey, ephemeralPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generate ephemeral keys: %w", ErrInvalidHandshake, err)
	}

	msg, err := BuildHandshakeMessage(sessionID, nonce, timestamp, ephemeralPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: build message: %w", ErrInvalidHandshake, err)
	}

	hash := sha256.Sum256(msg)

	signature, err := signer.SignPSS(hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: sign handshake: %w", ErrInvalidHandshake, err)
	}

	payload := &HandshakePayload{
		CameraCertificate:  camCert,
		EphemeralPublicKey: ephemeralPublicKey,
		SessionID:          sessionID,
		ConsumerNonce:      nonce,
		Timestamp:          timestamp,
		Signature:          signature,
	}

	return payload, ephemeralPrivateKey, nil
}

// VerifyHandshake вызывается на стороне Клиента при подключении камеры.
func VerifyHandshake(payload *HandshakePayload, rootCA *x509.Certificate, consumerNonce [16]byte, maxHandshakeAge time.Duration) error {
	if payload == nil {
		return fmt.Errorf("%w: payload is nil", ErrInvalidHandshake)
	}

	if payload.ConsumerNonce != consumerNonce {
		return fmt.Errorf("%w: consumer nonce mismatch", ErrInvalidHandshake)
	}

	// TODO: А если timestamp в будущем?
	if maxHandshakeAge <= 0 {
		return fmt.Errorf("%w: max handshake age must be positive", ErrInvalidHandshake)
	}
	ts := time.Unix(payload.Timestamp, 0)
	age := time.Since(ts)

	if age < 0 {
		return fmt.Errorf("%w: timestamp is from future", ErrInvalidHandshake)
	}

	if age > maxHandshakeAge {
		return fmt.Errorf("%w: timestamp is expired", ErrInvalidHandshake)
	}

	// проверили сертификат и публичный ключ
	cameraPublicKey, err := VerifyCameraCertificate(payload.CameraCertificate, rootCA)
	if err != nil {
		return fmt.Errorf("%w: verify camera certificate: %w", ErrInvalidHandshake, err)
	}

	msg, err := BuildHandshakeMessage(payload.SessionID, payload.ConsumerNonce, payload.Timestamp, payload.EphemeralPublicKey)
	if err != nil {
		return fmt.Errorf("%w: build message: %w", ErrInvalidHandshake, err)
	}

	hash := sha256.Sum256(msg)

	err = rsa.VerifyPSS(cameraPublicKey, stdcrypto.SHA256, hash[:], payload.Signature, nil)
	if err != nil {
		return fmt.Errorf("%w: invalid handshake signature: %w", ErrInvalidHandshake, err)
	}

	return nil
}
