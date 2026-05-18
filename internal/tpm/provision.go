package tpm

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// границы области идентификаторов, где TPM разрешает хранить постоянные объекты
const (
	minPersistentHandle uint32 = 0x81000000
	maxPersistentHandle uint32 = 0x81FFFFFF
)

func IsPersistentHandleNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "TPM_RC_HANDLE")
}
func ProvisionSigner(persistentHandle uint32, ownerAuth []byte, keyAuth []byte) (*Signer, error) {
	if err := validatePersistentHandle(persistentHandle); err != nil {
		return nil, err
	}

	tpmDevice, err := windowstpm.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: open tpm: %w", ErrTPMSigner, err)
	}

	created, err := createSigningPrimary(tpmDevice, ownerAuth, keyAuth)
	if err != nil {
		_ = tpmDevice.Close()
		return nil, err
	}

	createdHandle := tpm2.NamedHandle{
		Handle: created.ObjectHandle,
		Name:   created.Name,
	}

	evict := tpm2.EvictControl{
		Auth:             ownerHandle(ownerAuth),
		ObjectHandle:     &createdHandle,
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}
	if _, err := evict.Execute(tpmDevice); err != nil {
		flush := tpm2.FlushContext{FlushHandle: created.ObjectHandle}
		_, _ = flush.Execute(tpmDevice)
		_ = tpmDevice.Close()
		return nil, fmt.Errorf("%w: persist key: %w", ErrTPMSigner, err)
	}

	flush := tpm2.FlushContext{FlushHandle: created.ObjectHandle}
	if _, err := flush.Execute(tpmDevice); err != nil {
		_ = tpmDevice.Close()
		return nil, fmt.Errorf("%w: flush transient key: %w", ErrTPMSigner, err)
	}

	handle := tpm2.TPMHandle(persistentHandle)
	readPublic, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpmDevice)
	if err != nil {
		_ = tpmDevice.Close()
		return nil, fmt.Errorf("%w: read persisted public key: %w", ErrTPMSigner, err)
	}

	signer := &Signer{
		tpm: tpmDevice,
		handle: tpm2.NamedHandle{
			Handle: handle,
			Name:   readPublic.Name,
		},
		auth: append([]byte(nil), keyAuth...),
	}

	if _, err := signer.PublicKey(); err != nil {
		_ = tpmDevice.Close()
		return nil, err
	}

	return signer, nil
}

func createSigningPrimary(tpmDevice transport.TPM, ownerAuth []byte, keyAuth []byte) (*tpm2.CreatePrimaryResponse, error) {
	response, err := tpm2.CreatePrimary{
		PrimaryHandle: ownerHandle(ownerAuth),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: append([]byte(nil), keyAuth...),
				},
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgNull,
					},
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSAPSS,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSAPSS,
							&tpm2.TPMSSigSchemeRSAPSS{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
					// KeyBits:  3072,
					// Exponent: 65537,
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}),
	}.Execute(tpmDevice)
	if err != nil {
		return nil, fmt.Errorf("%w: create rsa signing key: %w", ErrTPMSigner, err)
	}

	return response, nil
}

func validatePersistentHandle(handle uint32) error {
	if handle < minPersistentHandle || handle > maxPersistentHandle {
		return fmt.Errorf("%w: persistent handle 0x%x is outside 0x%x-0x%x", ErrTPMSigner, handle, minPersistentHandle, maxPersistentHandle)
	}

	return nil
}

func ownerHandle(ownerAuth []byte) tpm2.AuthHandle {
	return tpm2.AuthHandle{
		Handle: tpm2.TPMRHOwner,
		Name:   tpm2.HandleName(tpm2.TPMRHOwner),
		Auth:   tpm2.PasswordAuth(ownerAuth),
	}
}
