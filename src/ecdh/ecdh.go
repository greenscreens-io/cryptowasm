/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package ecdh

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"reflect"
	"wasm/cryptowasm/src/lib"
)

// https://pkg.go.dev/crypto/ecdh in 1.20v when released

var stringType = reflect.TypeOf("")
var byteArrayType = reflect.TypeOf([]byte{})

var ecdhCache = lib.NewKeyPairStore[ecdh.PrivateKey, ecdh.PublicKey]()

// ImportPrivateKey imports ECDH key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPrivateKey(data any) (string, error) {

	var privateKey *ecdh.PrivateKey
	var err error

	if reflect.TypeOf(data) == stringType {
		privateKey, err = decodePrivKey(data.(string))
	}

	if reflect.TypeOf(data) == byteArrayType {
		privateKey, err = decodePrivKeyRaw(data.([]byte))
	}

	if err != nil {
		return "", err
	}

	if privateKey == nil {
		return "", errors.New(lib.ERR_KEY_NOT_IMPORTED)
	}

	return ecdhCache.SetKeyPair(privateKey, privateKey.PublicKey()), nil
}

// ImportPublicKey imports ECDH key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPublicKey(data any) (string, error) {

	var publicKey *ecdh.PublicKey
	var err error

	if reflect.TypeOf(data) == stringType {
		publicKey, err = decodePubKey(data.(string))
	}

	if reflect.TypeOf(data) == byteArrayType {
		publicKey, err = decodePubKeyRaw(data.([]byte))
	}

	if err != nil {
		return "", err
	}

	if publicKey == nil {
		return "", errors.New(lib.ERR_KEY_NOT_IMPORTED)
	}

	return ecdhCache.SetKeyPair(nil, publicKey), nil
}

// ImportJWK imports JSON format of JSON Web Key into GO structure;
// returns an id of key stored in internal cache
func ImportJWK(raw *map[string][]byte, curve string) (string, error) {

	fn, err := nameToCurve(curve)
	if err != nil {
		return "", err
	}

	isPublic := len((*raw)["d"]) == 0

	if isPublic {
		d := append([]byte{4}, (*raw)["x"]...)
		d = append(d, (*raw)["y"]...)
		k, err := fn.NewPublicKey(d)
		if err != nil {
			return "", err
		}
		return ecdhCache.SetKeyPair(nil, k), nil
	} else {
		k, err := fn.NewPrivateKey((*raw)["d"])
		if err != nil {
			return "", err
		}
		return ecdhCache.SetKeyPair(k, k.PublicKey()), nil
	}

}

// ExportPrivateKey exports Go structure private key in one of supported formats (Binary,Base64,JWK)
// input is id of a key stored in intenal memory cache
func ExportPrivateKey(id string, fmt lib.Format) (any, error) {

	privateKey := ecdhCache.Private.Get(id)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	switch fmt {
	case lib.FormatPem:
		return encodePrivKey(privateKey)
	case lib.FormatJWK:
		return exportPrivateJWK(privateKey)
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

}

// ExportPublicKey exports Go structure public key in one of supported formats (Binary,Base64,JWK)
// input is id of a key stored in intenal memory cache
func ExportPublicKey(id string, fmt lib.Format) (any, error) {

	publicKey := ecdhCache.Public.Get(id)
	if publicKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	switch fmt {
	case lib.FormatRaw:
		return publicKey.Bytes(), nil
	case lib.FormatPem:
		return encodePubKey(publicKey)
	case lib.FormatJWK:
		return exportPublicJWK(publicKey)
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

}

// GenerateKey randomly generates a keypair based on allowed curve size
// Allowed sizes are 256, 384, 521, 25519
func GenerateKey(size int) (string, error) {

	curve, err := sizeToCurve(size)
	if err != nil {
		return "", err
	}

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	return ecdhCache.SetKeyPair(privateKey, privateKey.PublicKey()), nil
}

// DeriveKey derives a new key (mostly used for AES encryption)
// based on local private key, and imported public key
// Inputs are id's of keys stroed in cache
func DeriveKey(priv, pub string, bitLen int) ([]byte, error) {

	privateKey := ecdhCache.Private.Get(priv)
	publicKey := ecdhCache.Public.Get(pub)

	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND_PRV)
	}

	if publicKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND_PUB)
	}

	data, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}

	data = lib.TrimToBits(data, bitLen)

	return data, nil
}

// HasKey based on provided key id, checks if a key (public or private)
// exist in the memory cache
func HasKey(id string, pub bool) bool {
	return ecdhCache.Exists(id, pub)
}

// RemoveKey based on provided key id, removes a key from the cache
func RemoveKey(id string, pub bool) bool {
	return ecdhCache.Remove(id, pub)
}
