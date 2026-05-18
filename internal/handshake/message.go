package handshake

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

const (
	ProtocolVersion byte = 1

	NonceSize             = 16
	SessionIDSize         = 16
	RSAPSSSignatureSize   = 256
	MaxCertificateDERSize = 16 * 1024

	protocolVersionSize   = 1
	uint16Size            = 2
	timestampSize         = 8
	requestSize           = protocolVersionSize + NonceSize
	responseFixedTailSize = ed25519.PublicKeySize + SessionIDSize + NonceSize + timestampSize + uint16Size + RSAPSSSignatureSize
	responseMinSize       = protocolVersionSize + uint16Size + responseFixedTailSize
)

type Request struct {
	ProtocolVersion byte
	ConsumerNonce   [NonceSize]byte
}

type Response struct {
	CameraCertificateDER []byte
	EphemeralPublicKey   ed25519.PublicKey
	SessionID            [SessionIDSize]byte
	ConsumerNonce        [NonceSize]byte
	Timestamp            int64
	Signature            []byte
}

func EncodeRequest(request *Request) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}

	buf := make([]byte, 0, requestSize)
	buf = append(buf, request.ProtocolVersion)
	buf = append(buf, request.ConsumerNonce[:]...)

	return buf, nil
}

func DecodeRequest(data []byte) (*Request, error) {
	if len(data) != requestSize {
		return nil, fmt.Errorf("%w: request size is %d bytes, want %d", ErrInvalidHandshake, len(data), requestSize)
	}

	request := Request{ProtocolVersion: data[0]}
	copy(request.ConsumerNonce[:], data[1:])

	if err := validateRequest(&request); err != nil {
		return nil, err
	}
	return &request, nil
}

func EncodeResponse(response *Response) ([]byte, error) {
	if err := validateResponse(response); err != nil {
		return nil, err
	}

	buf := make([]byte, 0, encodedResponseSize(response))
	buf = append(buf, ProtocolVersion)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(response.CameraCertificateDER)))
	buf = append(buf, response.CameraCertificateDER...)
	buf = append(buf, response.EphemeralPublicKey...)
	buf = append(buf, response.SessionID[:]...)
	buf = append(buf, response.ConsumerNonce[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(response.Timestamp))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(response.Signature)))
	buf = append(buf, response.Signature...)

	return buf, nil
}

func DecodeResponse(data []byte) (*Response, error) {
	if len(data) < responseMinSize {
		return nil, fmt.Errorf("%w: message is truncated", ErrInvalidHandshake)
	}

	offset := 0
	version := data[offset]
	offset += protocolVersionSize
	if version != ProtocolVersion {
		return nil, fmt.Errorf("%w: protocol version is %d, want %d", ErrInvalidHandshake, version, ProtocolVersion)
	}

	certificateSize := int(binary.BigEndian.Uint16(data[offset : offset+uint16Size]))
	offset += uint16Size
	if certificateSize == 0 || certificateSize > MaxCertificateDERSize {
		return nil, fmt.Errorf("%w: certificate size is %d bytes", ErrInvalidHandshake, certificateSize)
	}
	if len(data) != offset+certificateSize+responseFixedTailSize {
		return nil, fmt.Errorf("%w: response has trailing or missing bytes", ErrInvalidHandshake)
	}

	response := &Response{
		CameraCertificateDER: append([]byte(nil), data[offset:offset+certificateSize]...),
	}
	offset += certificateSize

	response.EphemeralPublicKey = append(ed25519.PublicKey(nil), data[offset:offset+ed25519.PublicKeySize]...)
	offset += ed25519.PublicKeySize

	copy(response.SessionID[:], data[offset:offset+SessionIDSize])
	offset += SessionIDSize

	copy(response.ConsumerNonce[:], data[offset:offset+NonceSize])
	offset += NonceSize

	response.Timestamp = int64(binary.BigEndian.Uint64(data[offset : offset+timestampSize]))
	offset += timestampSize

	signatureSize := int(binary.BigEndian.Uint16(data[offset : offset+uint16Size]))
	offset += uint16Size
	if signatureSize != RSAPSSSignatureSize {
		return nil, fmt.Errorf("%w: signature size is %d bytes, want %d", ErrInvalidHandshake, signatureSize, RSAPSSSignatureSize)
	}

	response.Signature = append([]byte(nil), data[offset:offset+signatureSize]...)

	if err := validateResponse(response); err != nil {
		return nil, err
	}

	return response, nil
}

func validateRequest(request *Request) error {
	if request == nil {
		return fmt.Errorf("%w: request is nil", ErrInvalidHandshake)
	}
	if request.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: protocol version is %d, want %d", ErrInvalidHandshake, request.ProtocolVersion, ProtocolVersion)
	}
	if request.ConsumerNonce == [NonceSize]byte{} {
		return fmt.Errorf("%w: consumer nonce is empty", ErrInvalidHandshake)
	}

	return nil
}

func validateResponse(response *Response) error {
	if response == nil {
		return fmt.Errorf("%w: response is nil", ErrInvalidHandshake)
	}
	if len(response.CameraCertificateDER) == 0 {
		return fmt.Errorf("%w: camera certificate is empty", ErrInvalidHandshake)
	}
	if len(response.CameraCertificateDER) > MaxCertificateDERSize {
		return fmt.Errorf("%w: camera certificate is too large", ErrInvalidHandshake)
	}
	if len(response.EphemeralPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: ephemeral public key size is %d bytes, want %d", ErrInvalidHandshake, len(response.EphemeralPublicKey), ed25519.PublicKeySize)
	}
	if len(response.Signature) != RSAPSSSignatureSize {
		return fmt.Errorf("%w: signature size is %d bytes, want %d", ErrInvalidHandshake, len(response.Signature), RSAPSSSignatureSize)
	}
	if response.SessionID == [SessionIDSize]byte{} {
		return fmt.Errorf("%w: session id is empty", ErrInvalidHandshake)
	}
	if response.ConsumerNonce == [NonceSize]byte{} {
		return fmt.Errorf("%w: consumer nonce is empty", ErrInvalidHandshake)
	}
	if response.Timestamp <= 0 {
		return fmt.Errorf("%w: timestamp is invalid", ErrInvalidHandshake)
	}

	return nil
}

func encodedResponseSize(response *Response) int {
	return protocolVersionSize +
		uint16Size + len(response.CameraCertificateDER) +
		responseFixedTailSize
}
