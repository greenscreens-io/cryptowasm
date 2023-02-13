/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"reflect"
	"wasm/cryptojs/src/base"
	"wasm/cryptojs/src/lib"
)

var stringType = reflect.TypeOf("")
var byteArrayType = reflect.TypeOf([]byte{})

var ecdsaCache = lib.NewKeyPairStore[ecdsa.PrivateKey, ecdsa.PublicKey]()

// ImportPrivateKey imports ECDH key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPrivateKey(data any) (string, error) {

	var privateKey *ecdsa.PrivateKey
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

	return ecdsaCache.SetKeyPair(privateKey, &privateKey.PublicKey), nil
}

// ImportPublicKey imports ECDH key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPublicKey(data any) (string, error) {

	var publicKey *ecdsa.PublicKey
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

	return ecdsaCache.SetKeyPair(nil, publicKey), nil
}

// ImportJWK imports JSON format of JSON Web Key into GO structure;
// returns an id of key stored in internal cache
func ImportJWK(raw *map[string][]byte, curve string) (string, error) {

	if len((*raw)["d"]) == 0 {
		k, err := importPublicJWK(raw, curve)
		if err != nil {
			return "", err
		}
		return ecdsaCache.SetKeyPair(nil, k), nil
	} else {
		k, err := importPrivateJWK(raw, curve)
		if err != nil {
			return "", err
		}
		return ecdsaCache.SetKeyPair(k, &k.PublicKey), nil
	}

}

// ExportPrivateKey exports Go structure private key in one of supported formats (Binary,Base64,JWK)
// input is id of a key stored in intenal memory cache
func ExportPrivateKey(id string, fmt lib.Format) (any, error) {

	privateKey := ecdsaCache.Private.Get(id)
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

	publicKey := ecdsaCache.Public.Get(id)
	if publicKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	switch fmt {
	case lib.FormatRaw:
		return elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y), nil
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

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", err
	}

	return ecdsaCache.SetKeyPair(privateKey, &privateKey.PublicKey), nil
}

// HasKey based on provided key id, checks if a key (public or private)
// exist in the memory cache
func HasKey(id string, pub bool) bool {
	return ecdsaCache.Exists(id, pub)
}

// RemoveKey based on provided key id, removes a key from the cache
func RemoveKey(id string, pub bool) bool {
	return ecdsaCache.Remove(id, pub)
}

// web crypto api use r|s format instead of asn1
func Sign(id string, data []byte, size int, asn bool) ([]byte, error) {

	privateKey := ecdsaCache.Private.Get(id)
	if privateKey == nil {
		return nil, errors.New("no key")
	}

	hash := base.DataToHash(data, size)
	if asn {
		return ecdsa.SignASN1(rand.Reader, privateKey, hash)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, err
	}

	return toRaw(r.Bytes(), s.Bytes(), privateKey.Curve.Params().BitSize), nil
}

// web crypto api use r|s format instead of asn1
func Verify(id string, data, signature []byte, size int, asn bool) bool {

	publicKey := ecdsaCache.Public.Get(id)
	if publicKey == nil {
		return false
	}

	hash := base.DataToHash(data, size)
	if asn {
		return ecdsa.VerifyASN1(publicKey, hash, signature)
	}

	r, s := fromRaw(signature)
	return ecdsa.Verify(publicKey, hash, r, s)
}
