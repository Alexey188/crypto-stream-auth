package media

import (
	"crypto-stream-auth/internal/domain"
	"fmt"
	"io"
)

type PayloadReader struct {
	reader         io.Reader
	maxPayloadSize int
	buffer         []byte
}

func NewPayloadReader(reader io.Reader, maxPayloadSize int) *PayloadReader {
	if maxPayloadSize <= 0 {
		maxPayloadSize = domain.MaxFramePayloadSize
	}

	return &PayloadReader{
		reader:         reader,
		maxPayloadSize: maxPayloadSize,
		buffer:         make([]byte, maxPayloadSize),
	}
}

func (r *PayloadReader) NextPayload() ([]byte, error) {
	if r == nil || r.reader == nil {
		return nil, fmt.Errorf("%w: payload reader is nil", ErrMedia)
	}

	n, err := r.reader.Read(r.buffer)
	if n > 0 {
		return r.buffer[:n], nil
	}
	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("%w: empty payload read", ErrMedia)
}
