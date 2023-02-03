/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package base

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"hash"
)

func Hmac1Sign(data, key []byte) []byte {
	return sign(data, key, crypto.SHA1.New)
}

func Hmac256Sign(data, key []byte) []byte {
	return sign(data, key, crypto.SHA256.New)
}

func Hmac384Sign(data, key []byte) []byte {
	return sign(data, key, crypto.SHA384.New)
}

func Hmac512Sign(data, key []byte) []byte {
	return sign(data, key, crypto.SHA512.New)
}

func Hmac1Verify(data, mac, key []byte) bool {
	return verify(data, mac, key, crypto.SHA1.New)
}

func Hmac256Verify(data, mac, key []byte) bool {
	return verify(data, mac, key, crypto.SHA256.New)
}

func Hmac384Verify(data, mac, key []byte) bool {
	return verify(data, mac, key, crypto.SHA384.New)
}

func Hmac512Verify(data, mac, key []byte) bool {
	return verify(data, mac, key, crypto.SHA512.New)
}

func verify(message, messageMAC, key []byte, sha func() hash.Hash) bool {
	mac := hmac.New(sha, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func sign(message, key []byte, sha func() hash.Hash) []byte {
	mac := hmac.New(sha, key)
	mac.Write(message)
	return mac.Sum(nil)
}
