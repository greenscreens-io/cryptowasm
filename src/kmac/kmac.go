/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package kmac

import (
	"encoding/base64"
	"errors"
	"hash"
	"wasm/cryptowasm/src/lib"

	"golang.org/x/crypto/sha3"
)

var cache = lib.NewKeyStore[hash.Hash]()

func GenerateKey(size int) (string, error) {
	var key hash.Hash
	switch size {
	case 128:
		key = sha3.NewCShake128(nil, nil)
	case 256:
		key = sha3.NewCShake256(nil, nil)
	}
	return cache.Set(lib.RandomStr(lib.IdSize), &key), nil
}

// Sign with KMAC
func Sign(id string, nonce, tag, data []byte) ([]byte, error) {

	aead := cache.Get(id)
	if aead == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	//TODO

	return nil, nil
}

// Verify with KMAC
func Verify(id string, nonce, tag, data []byte) ([]byte, error) {

	aead := cache.Get(id)
	if aead == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	// TODO

	return nil, nil
}

// validate Encrypte/Decrypt nonce,tag arguments
func validate(nonce, tag []byte) error {

	if nonce != nil && len(nonce) != 12 {
		return errors.New(lib.ERR_INVALID_ARGS_LEN)
	}

	if tag != nil && len(tag) != 128 {
		return errors.New(lib.ERR_INVALID_ARGS_LEN)
	}

	return nil
}

// ImportKey in raw format
func ImportJWK(raw *map[string][]byte) (string, error) {
	rawKey := (*raw)["k"]
	return ImportKey(rawKey)
}

// ImportKey in raw format
func ImportKey(key []byte) (string, error) {

	keylen := len(key)
	ok := (keylen == 16) || (keylen == 32)
	if !ok {
		return "", errors.New(lib.ERR_INVALID_KEY_CHACHA)
	}

	var aead hash.Hash
	// TODO
	/*
		aead, err := sha3.New256(),
		if err != nil {
			return "", err
		}
	*/

	return cache.Set(lib.RandomStr(lib.IdSize), &aead), nil
}

// ExportKey in raw format
func ExportKey(id string, fmt lib.Format) (any, error) {

	aead := cache.Get(id)
	if aead == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	var rawKey []byte

	// TODO

	switch fmt {
	case lib.FormatRaw:
		return rawKey, nil
	case lib.FormatJWK:
		return exportJWK(rawKey), nil
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

}

func exportJWK(key []byte) (jwk map[string]any) {
	enc := base64.RawURLEncoding
	jwk = map[string]any{
		"k":   enc.EncodeToString(key[0:]),
		"use": "enc",
		"alg": "C20P",
		"kty": "oct",
		"ext": "true",
	}
	return jwk
}

// HasKey based on provided key id
// exist in the memory cache
func HasKey(id string) bool {
	return cache.Exist(id)
}

// RemoveKey based on provided key id, removes a key from the cache
func RemoveKey(id string) bool {
	return cache.Remove(id)
}
