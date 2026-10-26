/*
 * Copyright (C) 2015, 2026 Green Screens Ltd.
 */
package mlkem

import (
	"crypto"
	"crypto/mlkem"
)

const (
	MLKEM512  = "ML-KEM-512"
	MLKEM768  = "ML-KEM-768"
	MLKEM1024 = "ML-KEM-1024"
)

type EncapsulationKey interface {
	Bytes() []byte
	Encapsulate() (sharedKey, ciphertext []byte)
}

type DecapsulationKey interface {
	Bytes() []byte
	Decapsulate(ciphertext []byte) (sharedKey []byte, err error)
	EncapsulationKey() EncapsulationKey
	Encapsulator() crypto.Encapsulator
}

type wrap768 struct{ *mlkem.DecapsulationKey768 }

func (w wrap768) EncapsulationKey() EncapsulationKey {
	return pubWrap768{w.DecapsulationKey768.EncapsulationKey()}
}

type pubWrap768 struct{ *mlkem.EncapsulationKey768 }

func (pw pubWrap768) Encapsulate() ([]byte, []byte) {
	return pw.EncapsulationKey768.Encapsulate()
}

type wrap1024 struct{ *mlkem.DecapsulationKey1024 }

func (w wrap1024) EncapsulationKey() EncapsulationKey {
	return pubWrap1024{w.DecapsulationKey1024.EncapsulationKey()}
}

type pubWrap1024 struct{ *mlkem.EncapsulationKey1024 }

func (pw pubWrap1024) Encapsulate() ([]byte, []byte) {
	return pw.EncapsulationKey1024.Encapsulate()
}
