/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package base

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"wasm/cryptowasm/src/lib"
)

func MD5(data []byte) ([]byte, error) {
	return dosha(data, crypto.MD5.New())
}

func Sha1(data []byte) ([]byte, error) {
	return dosha(data, crypto.SHA1.New())
}

func Sha224(data []byte) ([]byte, error) {
	return dosha(data, crypto.SHA224.New())
}

func Sha256(data []byte) ([]byte, error) {
	return dosha(data, crypto.SHA256.New())
}

func Sha384(data []byte) ([]byte, error) {
	return dosha(data, crypto.SHA384.New())
}

func Sha512(data []byte) ([]byte, error) {
	return dosha(data, crypto.SHA512.New())
}

func dosha(data []byte, fn hash.Hash) ([]byte, error) {
	fn.Write(data)
	return fn.Sum(nil), nil
}

func SizeToAlg(size int) (crypto.Hash, error) {
	var alg crypto.Hash
	switch size {
	case 1, 20:
		alg = crypto.SHA1
	case 28, 224:
		alg = crypto.SHA224
	case 32, 256:
		alg = crypto.SHA256
	case 48, 384:
		alg = crypto.SHA384
	case 64, 512:
		alg = crypto.SHA512
	default:
		return alg, errors.New(lib.ERR_INVALID_HASH)
	}
	return alg, nil
}

func DataToHash(data []byte, size int) []byte {
	var hash []byte
	switch size {
	case 1, 20:
		v0 := sha1.Sum(data)
		hash = v0[:]
	case 28, 224:
		v1 := sha256.Sum224(data)
		hash = v1[:]
	case 32, 256:
		v2 := sha256.Sum256(data)
		hash = v2[:]
	case 48, 384:
		v3 := sha512.Sum384(data)
		hash = v3[:]
	case 64, 512:
		v4 := sha512.Sum512(data)
		hash = v4[:]
	case 65, 521:
		v5 := sha512.Sum512(data)
		hash = v5[:]
	default:
		hash = []byte{}
	}
	return hash
}
