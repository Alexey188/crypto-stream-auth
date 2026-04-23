package domain

import (
	"encoding/binary"
)

type VideoFrame struct {
	SessionID uint32
	Sequence  uint32 // Это счетчик кадров
	Timestamp int64
	Payload   []byte
	Signature [64]byte
}

func (f *VideoFrame) BytesToSign() []byte {

	capacity := 16 + len(f.Payload)

	buf := make([]byte, capacity)

	binary.BigEndian.PutUint32(buf[0:4], f.SessionID)
	binary.BigEndian.PutUint32(buf[4:8], f.Sequence)
	binary.BigEndian.PutUint64(buf[8:16], uint64(f.Timestamp))

	copy(buf[16:], f.Payload)

	return buf
}
