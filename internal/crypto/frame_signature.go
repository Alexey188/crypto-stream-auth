package crypto

import (
	"crypto-stream-auth/internal/domain"
	"crypto/ed25519"
	"errors"
	"fmt"
)

var ErrFrameSignature = errors.New("frame signature")

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

	copy(frame.Signature[:], ed25519.Sign(privateKey, frame.BytesToSign()))
	return nil
}

func VerifyFrameSignature(publicKey ed25519.PublicKey, frame *domain.VideoFrame) error {
	if frame == nil {
		return fmt.Errorf("%w: video frame is nil", ErrFrameSignature)
	}
	if publicKey == nil {
		return fmt.Errorf("%w: public key is nil", ErrFrameSignature)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid public key size", ErrFrameSignature)
	}
	if !ed25519.Verify(publicKey, frame.BytesToSign(), frame.Signature[:]) {
		return fmt.Errorf("%w: invalid signature for sequence %d", ErrFrameSignature, frame.Sequence)
	}

	return nil
}
