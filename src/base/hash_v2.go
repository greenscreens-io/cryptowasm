/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package base

import (
	"golang.org/x/crypto/sha3"
)

func CShake_128(resultLen int, data, customization, N []byte) ([]byte, error) {
	return doCshake(resultLen, data, sha3.NewCShake128(N, customization))
}

func CShake_256(resultLen int, data, customization, N []byte) ([]byte, error) {
	return doCshake(resultLen, data, sha3.NewCShake256(N, customization))
}

func doCshake(resultLen int, data []byte, hash sha3.ShakeHash) ([]byte, error) {
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	output := make([]byte, resultLen)
	hash.Read(output)
	return output, nil
}
