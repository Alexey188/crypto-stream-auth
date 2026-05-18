package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

func EvictSigner(persistentHandle uint32, ownerAuth []byte) error {
	if err := validatePersistentHandle(persistentHandle); err != nil {
		return err
	}

	tpmDevice, err := windowstpm.Open()
	if err != nil {
		return fmt.Errorf("%w: open tpm: %w", ErrTPMSigner, err)
	}
	defer tpmDevice.Close()

	handle := tpm2.TPMHandle(persistentHandle)
	readPublic, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpmDevice)
	if err != nil {
		return fmt.Errorf("%w: read persistent key: %w", ErrTPMSigner, err)
	}

	objectHandle := tpm2.NamedHandle{
		Handle: handle,
		Name:   readPublic.Name,
	}

	evict := tpm2.EvictControl{
		Auth:             ownerHandle(ownerAuth),
		ObjectHandle:     &objectHandle,
		PersistentHandle: handle,
	}
	if _, err := evict.Execute(tpmDevice); err != nil {
		return fmt.Errorf("%w: evict persistent key: %w", ErrTPMSigner, err)
	}

	return nil
}
