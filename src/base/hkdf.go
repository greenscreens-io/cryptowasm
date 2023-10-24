/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package base

import (
	"io"
	"wasm/cryptowasm/src/lib"

	"golang.org/x/crypto/hkdf"
)

// GenerateHKDF generates a key from master key.
// Salt parameter length must be equal to the size of SHA-x algorithm (dividable by 8)
// For available lengths, check SizeToAlg() function
func GenerateHKDF(secret, salt, info []byte, size int) ([]byte, error) {

	rdr, err := generateHKDFKey(secret, salt, info)
	if err != nil {
		return nil, err
	}

	len, extra := lib.BitsToBytes(size)
	key := make([]byte, len)
	if _, err := io.ReadFull(rdr, key); err != nil {
		return nil, err
	}

	if extra > 0 {
		key = lib.TrimToBits(key, size)
	}

	return key, nil
}

func generateHKDFKey(secret, salt, info []byte) (io.Reader, error) {

	hashLen := len(salt)
	alg, err := SizeToAlg(hashLen)
	if err != nil {
		return nil, err
	}

	return hkdf.New(alg.New, secret, salt, info), nil
}
