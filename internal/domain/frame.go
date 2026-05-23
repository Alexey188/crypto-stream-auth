package domain

import "encoding/binary"

const (
	SessionIDSize       = 16
	FrameSignatureSize  = 64
	MaxFramePayloadSize = 256 * 1024
)

type SessionID = [SessionIDSize]byte
type FrameSignature = [FrameSignatureSize]byte

type VideoFrame struct {
	SessionID SessionID
	Sequence  uint64
	Timestamp int64
	Payload   []byte
	Signature FrameSignature
}

func (f *VideoFrame) BytesToSign() []byte {
	buf := make([]byte, 0, SessionIDSize+8+8+len(f.Payload))
	buf = append(buf, f.SessionID[:]...)
	buf = binary.BigEndian.AppendUint64(buf, f.Sequence)
	buf = binary.BigEndian.AppendUint64(buf, uint64(f.Timestamp))
	buf = append(buf, f.Payload...)
	return buf
}
