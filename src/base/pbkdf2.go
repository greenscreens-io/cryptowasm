/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package base

import (
	"wasm/cryptowasm/src/lib"

	"golang.org/x/crypto/pbkdf2"
)

// GeneratePBKDF2 generates a random password based on length, iterations and initial random salt
func GeneratePBKDF2(secret, salt []byte, iter, keyLen, hashLen int) ([]byte, error) {

	alg, err := SizeToAlg(hashLen)
	if err != nil {
		return nil, err
	}

	data := pbkdf2.Key(secret, salt, iter, keyLen, alg.New)
	data = lib.TrimToBits(data, keyLen)
	return data, nil
}
