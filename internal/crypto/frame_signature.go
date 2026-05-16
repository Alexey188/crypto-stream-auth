package crypto

import (
	"crypto-stream-auth/internal/domain"
	"crypto/ed25519"
	"errors"
	"fmt"
)

var (
	ErrFrameSignature = errors.New("frame signature")
)

// SignFrame генерирует подпись для видеокадра, используя приватный ключ сессии.
// Результат помещается в поле frame.Signature.
func SignFrameSignature(privateKey ed25519.PrivateKey, frame *domain.VideoFrame) error {
	if frame == nil {
		return fmt.Errorf("%w: video frame is nil", ErrFrameSignature)
	}
	if privateKey == nil {
		return fmt.Errorf("%w: private key is nil", ErrFrameSignature)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: invalid private key size", ErrFrameSignature)
	}
	bytesToSign := frame.BytesToSign()

	signature := ed25519.Sign(privateKey, bytesToSign)

	copy(frame.Signature[:], signature)

	return nil
}

// VerifyFrame проверяет, является ли подпись видеокадра действительной для его содержимого,
// используя публичный ключ сессии.
func VerifyFrameSignature(publicKey ed25519.PublicKey, frame *domain.VideoFrame) (bool, error) {
	if frame == nil {
		return false, fmt.Errorf("%w: video frame is nil", ErrFrameSignature)
	}
	if publicKey == nil {
		return false, fmt.Errorf("%w: public key is nil", ErrFrameSignature)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("%w: invalid public key size", ErrFrameSignature)
	}

	bytesToVerify := frame.BytesToSign()

	signature := frame.Signature[:]

	if !ed25519.Verify(publicKey, bytesToVerify, signature) {
		return false, fmt.Errorf("%w: invalid signature for sequence %d", ErrFrameSignature, frame.Sequence)
	}

	return true, nil
}
