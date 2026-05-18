package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"io"

	"crypto-stream-auth/internal/domain"
	"crypto-stream-auth/internal/handshake"

	quic "github.com/quic-go/quic-go"
)

const (
	MaxFramePayloadSize = 2 * 1024 * 1024

	uint32Size             = 4
	uint64Size             = 8
	frameHeaderSize        = handshake.SessionIDSize + uint64Size + uint64Size + uint32Size
	minEncodedFrameSize    = frameHeaderSize + ed25519.SignatureSize
	maxEncodedFrameSize    = frameHeaderSize + MaxFramePayloadSize + ed25519.SignatureSize
	framePayloadLengthFrom = handshake.SessionIDSize + uint64Size + uint64Size
)

func EncodeFrame(frame *domain.VideoFrame) ([]byte, error) {
	if err := validateFrameForTransport(frame); err != nil {
		return nil, err
	}

	data := make([]byte, 0, encodedFrameSize(frame))
	data = append(data, frame.SessionID[:]...)
	data = binary.BigEndian.AppendUint64(data, frame.Sequence)
	data = binary.BigEndian.AppendUint64(data, uint64(frame.Timestamp))
	data = binary.BigEndian.AppendUint32(data, uint32(len(frame.Payload)))
	data = append(data, frame.Payload...)
	data = append(data, frame.Signature[:]...)

	return data, nil
}

func DecodeFrame(data []byte) (*domain.VideoFrame, error) {
	if len(data) < minEncodedFrameSize {
		return nil, fmt.Errorf("%w: frame is truncated", ErrTransport)
	}
	if len(data) > maxEncodedFrameSize {
		return nil, fmt.Errorf("%w: frame is too large", ErrTransport)
	}

	payloadSize := int(binary.BigEndian.Uint32(data[framePayloadLengthFrom : framePayloadLengthFrom+uint32Size]))
	if payloadSize > MaxFramePayloadSize {
		return nil, fmt.Errorf("%w: frame payload is too large", ErrTransport)
	}
	if len(data) != frameHeaderSize+payloadSize+ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: frame has trailing or missing bytes", ErrTransport)
	}

	offset := 0
	frame := &domain.VideoFrame{}

	copy(frame.SessionID[:], data[offset:offset+handshake.SessionIDSize])
	offset += handshake.SessionIDSize

	frame.Sequence = binary.BigEndian.Uint64(data[offset : offset+uint64Size])
	offset += uint64Size

	frame.Timestamp = int64(binary.BigEndian.Uint64(data[offset : offset+uint64Size]))
	offset += uint64Size + uint32Size

	frame.Payload = append([]byte(nil), data[offset:offset+payloadSize]...)
	offset += payloadSize

	copy(frame.Signature[:], data[offset:offset+ed25519.SignatureSize])

	if err := validateFrameForTransport(frame); err != nil {
		return nil, err
	}

	return frame, nil
}

func WriteFrame(stream *quic.Stream, frame *domain.VideoFrame) error {
	if err := validateFrameForTransport(frame); err != nil {
		return err
	}
	if stream == nil {
		return fmt.Errorf("%w: stream is nil", ErrTransport)
	}

	header := make([]byte, 0, frameHeaderSize)
	header = append(header, frame.SessionID[:]...)
	header = binary.BigEndian.AppendUint64(header, frame.Sequence)
	header = binary.BigEndian.AppendUint64(header, uint64(frame.Timestamp))
	header = binary.BigEndian.AppendUint32(header, uint32(len(frame.Payload)))

	if err := writeAll(stream, header); err != nil {
		return fmt.Errorf("%w: write frame header: %w", ErrTransport, err)
	}
	if err := writeAll(stream, frame.Payload); err != nil {
		return fmt.Errorf("%w: write frame payload: %w", ErrTransport, err)
	}
	if err := writeAll(stream, frame.Signature[:]); err != nil {
		return fmt.Errorf("%w: write frame signature: %w", ErrTransport, err)
	}

	return nil
}

func ReadFrame(ctx context.Context, stream *quic.Stream) (*domain.VideoFrame, error) {
	if stream == nil {
		return nil, fmt.Errorf("%w: stream is nil", ErrTransport)
	}

	header := make([]byte, frameHeaderSize)
	if err := readFull(ctx, stream, header); err != nil {
		return nil, fmt.Errorf("%w: read frame header: %w", ErrTransport, err)
	}

	payloadSize := int(binary.BigEndian.Uint32(header[framePayloadLengthFrom : framePayloadLengthFrom+uint32Size]))
	if payloadSize > MaxFramePayloadSize {
		return nil, fmt.Errorf("%w: frame payload is too large", ErrTransport)
	}

	frame := &domain.VideoFrame{}
	offset := 0

	copy(frame.SessionID[:], header[offset:offset+handshake.SessionIDSize])
	offset += handshake.SessionIDSize

	frame.Sequence = binary.BigEndian.Uint64(header[offset : offset+uint64Size])
	offset += uint64Size

	frame.Timestamp = int64(binary.BigEndian.Uint64(header[offset : offset+uint64Size]))

	frame.Payload = make([]byte, payloadSize)
	if err := readFull(ctx, stream, frame.Payload); err != nil {
		return nil, fmt.Errorf("%w: read frame payload: %w", ErrTransport, err)
	}

	if err := readFull(ctx, stream, frame.Signature[:]); err != nil {
		return nil, fmt.Errorf("%w: read frame signature: %w", ErrTransport, err)
	}

	if err := validateFrameForTransport(frame); err != nil {
		return nil, err
	}

	return frame, nil
}

func validateFrameForTransport(frame *domain.VideoFrame) error {
	if frame == nil {
		return fmt.Errorf("%w: frame is nil", ErrTransport)
	}
	if frame.SessionID == [handshake.SessionIDSize]byte{} {
		return fmt.Errorf("%w: frame session id is empty", ErrTransport)
	}
	if frame.Timestamp <= 0 {
		return fmt.Errorf("%w: frame timestamp is invalid", ErrTransport)
	}
	if len(frame.Payload) == 0 {
		return fmt.Errorf("%w: frame payload is empty", ErrTransport)
	}
	if len(frame.Payload) > MaxFramePayloadSize {
		return fmt.Errorf("%w: frame payload is too large", ErrTransport)
	}

	return nil
}

func encodedFrameSize(frame *domain.VideoFrame) int {
	return frameHeaderSize + len(frame.Payload) + ed25519.SignatureSize
}

func writeAll(stream *quic.Stream, data []byte) error {
	for len(data) > 0 {
		n, err := stream.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}

	return nil
}

func readFull(ctx context.Context, stream *quic.Stream, data []byte) error {
	result := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(stream, data)
		result <- err
	}()

	select {
	case <-ctx.Done():
		stream.CancelRead(0)
		return ctx.Err()
	case err := <-result:
		return err
	}
}
