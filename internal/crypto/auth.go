package crypto

import (
	"crypto-stream-auth/internal/domain" // Убедитесь, что это ваш правильный путь к модулю
	"crypto/ed25519"
	"fmt"
)

// SignFrame генерирует подпись для видеокадра, используя приватный ключ сессии.
// Результат помещается в поле frame.Signature.
func SignFrame(privateKey ed25519.PrivateKey, frame *domain.VideoFrame) error {

	bytesToSign := frame.BytesToSign()

	signature := ed25519.Sign(privateKey, bytesToSign)

	copy(frame.Signature[:], signature)

	return nil
}

// VerifyFrame проверяет, является ли подпись видеокадра действительной для его содержимого,
// используя публичный ключ сессии.
func VerifyFrame(publicKey ed25519.PublicKey, frame domain.VideoFrame) (bool, error) {
	bytesToVerify := frame.BytesToSign()

	signature := frame.Signature[:]

	if !ed25519.Verify(publicKey, bytesToVerify, signature) {
		return false, fmt.Errorf("ошибка верификации подписи для кадра с sequence %d", frame.Sequence)
	}

	return true, nil
}
