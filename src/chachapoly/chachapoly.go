/*
 * Copyright (C) 2015, 2026 Green Screens Ltd.
 */
package chachapoly

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"reflect"
	"unsafe"
	"wasm/cryptowasm/src/base"
	"wasm/cryptowasm/src/lib"

	"golang.org/x/crypto/chacha20poly1305"
)

var cache = lib.NewKeyStore[cipher.AEAD]()

func GenerateKey() (string, error) {

	key, err := base.Random(chacha20poly1305.KeySize)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	return cache.Set(lib.RandomStr(lib.IdSize), &aead), nil

}

// Encrypt with ChachaPoly using provided nonce(12), optional tag(128) and data
func Encrypt(id string, nonce, tag, data []byte) ([]byte, error) {

	aead := cache.Get(id)
	if aead == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	err := validate(nonce, tag)
	if err != nil {
		return nil, errors.New(lib.ERR_INVALID_ARGS_LEN)
	}

	ciphertextWithTag := (*aead).Seal(nil, nonce, data, tag)
	return ciphertextWithTag, nil
}

// Decrypt with ChachaPoly using provided nonce(12), optional tag(128) and data
func Decrypt(id string, nonce, tag, data []byte) ([]byte, error) {

	aead := cache.Get(id)
	if aead == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	err := validate(nonce, tag)
	if err != nil {
		return nil, errors.New(lib.ERR_INVALID_ARGS_LEN)
	}

	// return plaintext, error
	return (*aead).Open(nil, nonce, data, tag)
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

	if len(key) != chacha20poly1305.KeySize {
		return "", errors.New(lib.ERR_INVALID_KEY_CHACHA)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	return cache.Set(lib.RandomStr(lib.IdSize), &aead), nil
}

// ExportKey in raw format
func ExportKey(id string, fmt lib.Format) (any, error) {

	aead := cache.Get(id)
	if aead == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	var rawKey [chacha20poly1305.KeySize]byte

	v := reflect.ValueOf(aead).Elem()
	keyField := v.FieldByName("key")

	if keyField.IsValid() {
		ptr := unsafe.Pointer(keyField.UnsafeAddr())
		rawKey = *(*[chacha20poly1305.KeySize]byte)(ptr)
	} else {
		return nil, errors.New(lib.ERR_KEY_NOT_EXPORTED)
	}

	switch fmt {
	case lib.FormatRaw:
		return rawKey, nil
	case lib.FormatJWK:
		return exportJWK(rawKey), nil
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

}

func exportJWK(key [chacha20poly1305.KeySize]byte) (jwk map[string]any) {
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
