package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"crypto-stream-auth/internal/domain"
	"crypto-stream-auth/internal/handshake"

	quic "github.com/quic-go/quic-go"
)

const (
	uint32Size             = 4
	uint64Size             = 8
	frameHeaderSize        = handshake.SessionIDSize + uint64Size + uint64Size + uint32Size
	framePayloadLengthFrom = handshake.SessionIDSize + uint64Size + uint64Size
)

type FrameReadResult struct {
	StreamIndex int
	Frame       *domain.VideoFrame
	Err         error
}

func WriteFrame(stream *quic.Stream, frame *domain.VideoFrame) error {
	if err := validateFrameForWrite(frame); err != nil {
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
	if payloadSize > domain.MaxFramePayloadSize {
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

	return frame, nil
}

func ReadFramesFromStreams(ctx context.Context, streams []*quic.Stream) <-chan FrameReadResult {
	results := make(chan FrameReadResult, len(streams))

	var wg sync.WaitGroup
	wg.Add(len(streams))

	for i, stream := range streams {
		go func(streamIndex int, stream *quic.Stream) {
			defer wg.Done()
			for {
				frame, err := ReadFrame(ctx, stream)
				if err != nil {
					sendFrameReadResult(ctx, results, FrameReadResult{
						StreamIndex: streamIndex,
						Err:         err,
					})
					return
				}

				if !sendFrameReadResult(ctx, results, FrameReadResult{
					StreamIndex: streamIndex,
					Frame:       frame,
				}) {
					return
				}
			}
		}(i, stream)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

func validateFrameForWrite(frame *domain.VideoFrame) error {
	if frame == nil {
		return fmt.Errorf("%w: frame is nil", ErrTransport)
	}
	if len(frame.Payload) > domain.MaxFramePayloadSize {
		return fmt.Errorf("%w: frame payload is too large", ErrTransport)
	}

	return nil
}

func sendFrameReadResult(ctx context.Context, results chan<- FrameReadResult, result FrameReadResult) bool {
	select {
	case results <- result:
		return true
	case <-ctx.Done():
		return false
	}
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
	if err := ctx.Err(); err != nil {
		stream.CancelRead(0)
		return err
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetReadDeadline(deadline); err != nil {
			return err
		}
		defer stream.SetReadDeadline(time.Time{})
	}

	_, err := io.ReadFull(stream, data)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}

	return nil
}
