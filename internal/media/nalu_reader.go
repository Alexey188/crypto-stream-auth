package media

import (
	"bufio"
	"crypto-stream-auth/internal/domain"
	"fmt"
	"io"
)

const (
	DefaultMaxNALUSize = 2 * 1024 * 1024
)

var h264StartCode = []byte{0x00, 0x00, 0x00, 0x01}

type AnnexBNALUReader struct {
	reader      *bufio.Reader
	maxNALUSize int
	started     bool
}

func NewAnnexBNALUReader(reader io.Reader, maxNALUSize int) *AnnexBNALUReader {
	if maxNALUSize <= 0 {
		maxNALUSize = DefaultMaxNALUSize
	}

	naluReader := &AnnexBNALUReader{
		maxNALUSize: maxNALUSize,
	}
	if reader != nil {
		naluReader.reader = bufio.NewReader(reader)
	}

	return naluReader
}

func (r *AnnexBNALUReader) NextNALU() ([]byte, error) {
	if r == nil || r.reader == nil {
		return nil, fmt.Errorf("%w: nalu reader is nil", ErrMedia)
	}

	if !r.started {
		if err := r.skipUntilStartCode(); err != nil {
			return nil, err
		}
		r.started = true
	}

	return r.readNALU()
}

func (r *AnnexBNALUReader) skipUntilStartCode() error {
	zeroCount := 0

	for {
		b, err := r.reader.ReadByte()
		if err != nil {
			return err
		}

		if b == 0 {
			zeroCount++
			continue
		}

		if b == 1 && zeroCount >= 2 {
			return nil
		}

		zeroCount = 0
	}
}

func (r *AnnexBNALUReader) readNALU() ([]byte, error) {
	nalu := make([]byte, 0, 4096)
	zeroCount := 0

	for {
		b, err := r.reader.ReadByte()
		if err != nil {
			if err == io.EOF && len(nalu) > 0 {
				return nalu, nil
			}
			return nil, err
		}

		if b == 0 {
			nalu = append(nalu, b)
			zeroCount++
			if len(nalu) > r.maxNALUSize {
				return nil, fmt.Errorf("%w: nalu is too large", ErrMedia)
			}
			continue
		}

		if b == 1 && zeroCount >= 2 {
			nalu = nalu[:len(nalu)-zeroCount]
			if len(nalu) == 0 {
				zeroCount = 0
				continue
			}
			return nalu, nil
		}

		nalu = append(nalu, b)
		zeroCount = 0
		if len(nalu) > r.maxNALUSize {
			return nil, fmt.Errorf("%w: nalu is too large", ErrMedia)
		}
	}
}

type H264PayloadReader struct {
	nalus          *AnnexBNALUReader
	pendingNALU    []byte
	maxPayloadSize int
}

func NewH264PayloadReader(reader io.Reader, maxNALUSize int, maxPayloadSize int) *H264PayloadReader {
	if maxPayloadSize <= 0 {
		maxPayloadSize = domain.MaxFramePayloadSize
	}

	return &H264PayloadReader{
		nalus:          NewAnnexBNALUReader(reader, maxNALUSize),
		maxPayloadSize: maxPayloadSize,
	}
}

func (r *H264PayloadReader) NextPayload() ([]byte, error) {
	if r == nil || r.nalus == nil {
		return nil, fmt.Errorf("%w: payload reader is nil", ErrMedia)
	}

	payload := make([]byte, 0, 64*1024)
	hasVCL := false

	if len(r.pendingNALU) > 0 {
		payload = appendNALU(payload, r.pendingNALU)
		if len(payload) > r.maxPayloadSize {
			return nil, fmt.Errorf("%w: payload is too large", ErrMedia)
		}
		hasVCL = isVCLNALU(r.pendingNALU)
		r.pendingNALU = nil
	}

	for {
		nalu, err := r.nalus.NextNALU()
		if err != nil {
			if err == io.EOF && len(payload) > 0 {
				return payload, nil
			}
			return nil, err
		}
		if len(nalu) == 0 {
			continue
		}

		naluIsVCL := isVCLNALU(nalu)
		if naluIsVCL && hasVCL {
			r.pendingNALU = append([]byte(nil), nalu...)
			return payload, nil
		}

		payload = appendNALU(payload, nalu)
		if len(payload) > r.maxPayloadSize {
			return nil, fmt.Errorf("%w: payload is too large", ErrMedia)
		}
		if naluIsVCL {
			hasVCL = true
		}
	}
}

func appendNALU(dst []byte, nalu []byte) []byte {
	dst = append(dst, h264StartCode...)
	return append(dst, nalu...)
}

func isVCLNALU(nalu []byte) bool {
	if len(nalu) == 0 {
		return false
	}

	naluType := nalu[0] & 0x1F
	return naluType >= 1 && naluType <= 5
}
