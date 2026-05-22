package tpm

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

var ErrTPMSigner = errors.New("tpm signer")

type Signer struct {
	tpm    transport.TPMCloser
	handle tpm2.NamedHandle
	auth   []byte
}

func OpenSigner(persistentHandle uint32, auth []byte) (*Signer, error) {
	if persistentHandle == 0 {
		return nil, fmt.Errorf("%w: persistent handle is empty", ErrTPMSigner)
	}

	tpmDevice, err := windowstpm.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: open tpm: %w", ErrTPMSigner, err)
	}

	handle := tpm2.TPMHandle(persistentHandle)
	readPublic, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpmDevice)
	if err != nil {
		_ = tpmDevice.Close()
		return nil, fmt.Errorf("%w: read public key: %w", ErrTPMSigner, err)
	}

	signer := &Signer{
		tpm: tpmDevice,
		handle: tpm2.NamedHandle{
			Handle: handle,
			Name:   readPublic.Name,
		},
		auth: append([]byte(nil), auth...),
	}

	if _, err := signer.PublicKey(); err != nil {
		_ = tpmDevice.Close()
		return nil, err
	}

	return signer, nil
}

func (s *Signer) PublicKey() (*rsa.PublicKey, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: signer is nil", ErrTPMSigner)
	}
	if s.tpm == nil {
		return nil, fmt.Errorf("%w: tpm device is nil", ErrTPMSigner)
	}

	readPublic, err := tpm2.ReadPublic{
		ObjectHandle: s.handle,
	}.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: read public key: %w", ErrTPMSigner, err)
	}

	public, err := readPublic.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("%w: decode public area: %w", ErrTPMSigner, err)
	}

	rsaDetails, err := public.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("%w: public key is not rsa: %w", ErrTPMSigner, err)
	}

	rsaUnique, err := public.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("%w: public key unique field is not rsa: %w", ErrTPMSigner, err)
	}

	publicKey, err := tpm2.RSAPub(rsaDetails, rsaUnique)
	if err != nil {
		return nil, fmt.Errorf("%w: convert public key: %w", ErrTPMSigner, err)
	}

	if publicKey.N == nil {
		return nil, fmt.Errorf("%w: rsa modulus is nil", ErrTPMSigner)
	}
	if publicKey.N.BitLen() != signingRSAKeyBits {
		return nil, fmt.Errorf("%w: rsa key size is %d bits, want %d", ErrTPMSigner, publicKey.N.BitLen(), signingRSAKeyBits)
	}

	return publicKey, nil
}

func (s *Signer) SignPSS(digest []byte) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: signer is nil", ErrTPMSigner)
	}
	if s.tpm == nil {
		return nil, fmt.Errorf("%w: tpm device is nil", ErrTPMSigner)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w: digest size is %d bytes, want %d", ErrTPMSigner, len(digest), sha256.Size)
	}

	sign, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: s.handle.Handle,
			Name:   s.handle.Name,
			Auth:   tpm2.PasswordAuth(s.auth),
		},
		Digest: tpm2.TPM2BDigest{
			Buffer: digest,
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSAPSS,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: sign digest: %w", ErrTPMSigner, err)
	}

	signature, err := sign.Signature.Signature.RSAPSS()
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not rsa-pss: %w", ErrTPMSigner, err)
	}

	return append([]byte(nil), signature.Sig.Buffer...), nil
}

func (s *Signer) Close() error {
	if s == nil || s.tpm == nil {
		return nil
	}

	err := s.tpm.Close()
	s.tpm = nil
	if err != nil {
		return fmt.Errorf("%w: close tpm: %w", ErrTPMSigner, err)
	}

	return nil
}
