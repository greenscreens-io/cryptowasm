/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package lib

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// BitsToBytes calculate bits to byte|bit remainging
func BitsToBytes(bitLen int) (int, int) {
	bits := bitLen % 8
	bytes := int(bitLen / 8)
	if bits > 0 {
		return bytes + 1, bits
	}
	return bytes, 0
}

// BitsCalc used for raw key export, modifies last byte to be compatible with Web Crypto API export
func BitsCalc(val byte, bits int) byte {
	return ((255 >> bits) ^ 255) & val
}

// TrimToBits trim byte array to bit length
func TrimToBits(data []byte, bitLen int) []byte {
	len, extra := BitsToBytes(bitLen)
	raw := data[0:len]
	if extra > 0 {
		raw[len-1] = BitsCalc(raw[len-1], extra)
	}
	return raw
}

// random generate random bytes by given size
func random(size int) []byte {
	genkey := make([]byte, size)
	_, err := rand.Read(genkey)
	if err != nil {
		return nil
	}
	return genkey
}

// randomStr generate random string by given size
func randomStr(size int) string {
	return hex.EncodeToString(random(size))[:size]
}

// DecodeJWK decode string:string key:value pair to string:[]byte; received from JS
func DecodeJWK(data *map[string]any) error {

	enc := base64.RawURLEncoding

	for key, element := range *data {

		if len(key) < 3 {

			v, err := enc.DecodeString(element.(string))
			if err != nil {
				return err
			}

			(*data)[key] = v
		}
	}

	return nil
}
