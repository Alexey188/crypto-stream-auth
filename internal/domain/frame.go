package domain

import (
	"encoding/binary"
)

type VideoFrame struct {
	SessionID [16]byte
	Sequence  uint64 // Это счетчик кадров
	Timestamp int64
	Payload   []byte
	Signature [64]byte
}

func (f *VideoFrame) BytesToSign() []byte {

	buf := make([]byte, 0, 16+8+8+len(f.Payload))

	buf = append(buf, f.SessionID[:]...)
	buf = binary.BigEndian.AppendUint64(buf, f.Sequence)
	buf = binary.BigEndian.AppendUint64(buf, uint64(f.Timestamp))
	buf = append(buf, f.Payload...)

	return buf
}
