/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package base

import (
	"errors"
	"wasm/cryptowasm/src/lib"

	"golang.org/x/crypto/pbkdf2"
)

// GeneratePBKDF2 generates a random password based on length, iterations and initial random salt
func GeneratePBKDF2(secret, salt []byte, iter, keyLen, hashLen int) ([]byte, error) {
	if iter <= 0 || keyLen <= 0 {
		return nil, errors.New(lib.ERR_INVALID_ARGS)
	}

	alg, err := SizeToAlg(hashLen)
	if err != nil {
		return nil, err
	}

	keyBytes, _ := lib.BitsToBytes(keyLen)
	data := pbkdf2.Key(secret, salt, iter, keyBytes, alg.New)
	data = lib.TrimToBits(data, keyLen)
	return data, nil
}
