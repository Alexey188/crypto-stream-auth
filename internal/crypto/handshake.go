package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrInvalidHandshake = errors.New("invalid handshake")
)

// HandshakePayload — это пакет данных, который Камера отправляет Клиенту при подключении.
type HandshakePayload struct {
	CameraCertificate *x509.Certificate
	PublicKey         ed25519.PublicKey
	SessionID         [16]byte
	ConsumerNonce     [16]byte
	Timestamp         int64
	Signature         []byte
}

// GenerateHandshake вызывается на стороне Камеры перед началом трансляции.
func GenerateHandshake(camCert *x509.Certificate, camPrivKey ed25519.PrivateKey, sessionID [16]byte,
	nonce [16]byte, timestamp int64) (*HandshakePayload, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	buf := make([]byte, 0, 16+16+8+len(publicKey))

	buf = append(buf, sessionID[:]...)
	buf = append(buf, nonce[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(timestamp))
	buf = append(buf, publicKey...)

	hash := sha256.Sum256(buf)

	signature := ed25519.Sign(camPrivKey, hash[:])

	payload := &HandshakePayload{
		CameraCertificate: camCert,
		PublicKey:         publicKey,
		SessionID:         sessionID,
		ConsumerNonce:     nonce,
		Timestamp:         timestamp,
		Signature:         signature,
	}

	return payload, privateKey, nil
}

// VerifyHandshake вызывается на стороне Клиента при подключении камеры.
func VerifyHandshake(payload *HandshakePayload, rootCA *x509.Certificate) error {
	if payload == nil {
		return fmt.Errorf("%w: payload is nil", ErrInvalidHandshake)
	}

	if rootCA == nil {
		return fmt.Errorf("%w: root CA is nil", ErrInvalidHandshake)
	}

	if payload.CameraCertificate == nil {
		return fmt.Errorf("%w: Camera Certificate is nil", ErrInvalidHandshake)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCA)

	_, err := payload.CameraCertificate.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		return fmt.Errorf("%w: certificate verify error: %w", ErrInvalidHandshake, err)
	}

	if len(payload.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid public key size", ErrInvalidHandshake)
	}

	buf := make([]byte, 0, 16+16+8+len(payload.PublicKey))

	buf = append(buf, payload.SessionID[:]...)
	buf = append(buf, payload.ConsumerNonce[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(payload.Timestamp))
	buf = append(buf, payload.PublicKey...)

	hash := sha256.Sum256(buf)
	cameraPublicKey, ok := payload.CameraCertificate.PublicKey.(ed25519.PublicKey)

	if !ok {
		return fmt.Errorf("%w: camera public key is not Ed25519", ErrInvalidHandshake)
	}

	if len(cameraPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid camera public key size", ErrInvalidHandshake)
	}

	if !ed25519.Verify(cameraPublicKey, hash[:], payload.Signature) {
		return fmt.Errorf("%w: invalid handshake signature", ErrInvalidHandshake)
	}

	// TODO сделать проверку NONCE
	return nil
}
