package tpm

import "fmt"

const (
	MinPersistentHandle uint32 = 0x81000000
	MaxPersistentHandle uint32 = 0x81FFFFFF

	DefaultCameraKeyHandle uint32 = 0x81000001
)

func ValidatePersistentHandle(handle uint32) error {
	if handle < MinPersistentHandle || handle > MaxPersistentHandle {
		return fmt.Errorf("%w: persistent handle 0x%x is outside 0x%x-0x%x", ErrTPMSigner, handle, MinPersistentHandle, MaxPersistentHandle)
	}

	return nil
}
