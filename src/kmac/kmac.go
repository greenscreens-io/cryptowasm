/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package kmac

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"wasm/cryptowasm/src/base"
	"wasm/cryptowasm/src/lib"
)

type key struct {
	strength int
	raw      []byte
}

var cache = lib.NewKeyStore[key]()

func GenerateKey(strength int) (string, error) {
	keySize, err := keySizeForStrength(strength)
	if err != nil {
		return "", err
	}

	raw, err := base.Random(keySize)
	if err != nil {
		return "", err
	}

	entry := key{strength: strength, raw: raw}
	return cache.Set(lib.RandomStr(lib.IdSize), &entry), nil
}

// Sign returns a KMAC tag whose length is outputBits.
func Sign(id string, data []byte, outputBits int, customization ...[]byte) ([]byte, error) {
	entry := cache.Get(id)
	if entry == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}
	if len(customization) > 1 {
		return nil, errors.New("KMAC accepts at most one customization string")
	}
	if outputBits <= 0 || outputBits%8 != 0 {
		return nil, errors.New("KMAC output length must be a positive multiple of 8 bits")
	}

	return sum(entry, data, outputBits, customString(customization)), nil
}

// Verify compares tag against a KMAC tag of the same length.
func Verify(id string, data, tag []byte, customization ...[]byte) (bool, error) {
	entry := cache.Get(id)
	if entry == nil {
		return false, errors.New(lib.ERR_KEY_NOT_FOUND)
	}
	if len(customization) > 1 {
		return false, errors.New("KMAC accepts at most one customization string")
	}
	if len(tag) == 0 {
		return false, errors.New("KMAC tag must not be empty")
	}

	expected := sum(entry, data, len(tag)*8, customString(customization))
	return subtle.ConstantTimeCompare(tag, expected) == 1, nil
}

func sum(entry *key, data []byte, outputBits int, customization []byte) []byte {
	h := toAlgo(entry.strength, customization)
	_, _ = h.Write(wrapKey(entry.strength, entry.raw))
	_, _ = h.Write(data)
	_, _ = h.Write(rightEncode(uint64(outputBits)))
	result := make([]byte, outputBits/8)
	_, _ = h.Read(result)
	return result
}

func customString(customization [][]byte) []byte {
	if len(customization) == 0 {
		return nil
	}
	return customization[0]
}

func keySizeForStrength(strength int) (int, error) {
	switch strength {
	case 128:
		return 16, nil
	case 256:
		return 32, nil
	default:
		return 0, fmt.Errorf("invalid KMAC strength %d (expected 128 or 256)", strength)
	}
}

// ImportJWK imports the raw key in a JWK's "k" field.
func ImportJWK(raw *map[string][]byte) (string, error) {
	if raw == nil {
		return "", errors.New("missing KMAC JWK")
	}
	return ImportKey((*raw)["k"])
}

// ImportKey imports a raw 128- or 256-bit KMAC key.
func ImportKey(raw []byte) (string, error) {
	strength := 0
	switch len(raw) {
	case 16:
		strength = 128
	case 32:
		strength = 256
	default:
		return "", errors.New("invalid KMAC key size (expected 16 or 32 bytes)")
	}

	entry := key{strength: strength, raw: append([]byte(nil), raw...)}
	return cache.Set(lib.RandomStr(lib.IdSize), &entry), nil
}

// ExportKey exports a key in raw or JWK format.
func ExportKey(id string, format lib.Format) (any, error) {
	entry := cache.Get(id)
	if entry == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	raw := append([]byte(nil), entry.raw...)
	switch format {
	case lib.FormatRaw:
		return raw, nil
	case lib.FormatJWK:
		return exportJWK(raw, entry.strength), nil
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}
}

func exportJWK(raw []byte, strength int) map[string]any {
	return map[string]any{
		"k":   base64.RawURLEncoding.EncodeToString(raw),
		"use": "sig",
		"alg": fmt.Sprintf("KMAC%d", strength),
		"kty": "oct",
		"ext": true,
	}
}

// HasKey reports whether the key ID is present in the in-memory key store.
func HasKey(id string) bool {
	return cache.Exist(id)
}

// RemoveKey removes the key ID from the in-memory key store.
func RemoveKey(id string) bool {
	return cache.Remove(id)
}
