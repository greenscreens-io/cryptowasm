/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"wasm/cryptojs/src/lib"
)

// https://pkg.go.dev/crypto/ecdh in 1.20v when released

var stringType = reflect.TypeOf("")
var byteArrayType = reflect.TypeOf([]byte{})

var ed25519Cache = lib.NewKeyPairStore[ed25519.PrivateKey, ed25519.PublicKey]()

// ImportPrivateKey imports ECDH key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPrivateKey(data any) (string, error) {

	var privateKey *ed25519.PrivateKey
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

	return ed25519Cache.SetKeyPair(privateKey, nil), nil
}

// ImportPublicKey imports ECDH key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPublicKey(data any) (string, error) {

	var publicKey *ed25519.PublicKey
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

	return ed25519Cache.SetKeyPair(nil, publicKey), nil
}

// ImportJWK imports JSON format of JSON Web Key into GO structure;
// returns an id of key stored in internal cache
func ImportJWK(raw *map[string][]byte) (string, error) {

	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey

	isPublic := len((*raw)["d"]) == 0
	publicKey = (*raw)["x"]

	if isPublic {
		return ed25519Cache.SetKeyPair(nil, &publicKey), nil
	} else {
		privateKey = (*raw)["d"]
		return ed25519Cache.SetKeyPair(&privateKey, &publicKey), nil
	}

}

// ExportPrivateKey exports Go structure private key in one of supported formats (Binary,Base64,JWK)
// input is id of a key stored in intenal memory cache
func ExportPrivateKey(id string, fmt lib.Format) (any, error) {

	privateKey := ed25519Cache.Private.Get(id)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	switch fmt {
	case lib.FormatRaw:
		return encodePrivKeyRaw(privateKey)
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

	publicKey := ed25519Cache.Public.Get(id)
	if publicKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	switch fmt {
	case lib.FormatRaw:
		return encodePubKeyRaw(publicKey)
	case lib.FormatPem:
		return encodePubKey(publicKey)
	case lib.FormatJWK:
		return exportPublicJWK(publicKey)
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

}

// GenerateKey randomly generates a keypair based on allowed curve size
func GenerateKey() (string, error) {

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	return ed25519Cache.SetKeyPair(&privateKey, &publicKey), nil
}

// Sign creates a digital signature of provided data, signed with private key
// @priv id of a private key in memory cache
// @messsage data to sign
// @asn not used here
func Sign(priv string, message []byte, asn bool) ([]byte, error) {

	privateKey := ed25519Cache.Private.Get(priv)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND_PRV)
	}

	// result is r|s format
	signature := ed25519.Sign(*privateKey, message)

	/*
		if asn {
			r, s := fromRaw(signature)
			signature = ecdsa.encodeSignature(r.Bytes(c.N), s.Bytes(c.N))
		}
	*/

	return signature, nil
}

// Verify will check digital signature for provided data
// @priv id of a private key in memory cache
// @messsage data to verify
// @signature matching signature
// @asn not used here
func Verify(pub string, message, signature []byte, asn bool) (bool, error) {

	publicKey := ed25519Cache.Public.Get(pub)
	if publicKey == nil {
		return false, errors.New(lib.ERR_KEY_NOT_FOUND_PRV)
	}

	data := ed25519.Verify(*publicKey, message, signature)

	return data, nil
}

// HasKey based on provided key id, checks if a key (public or private)
// exist in the memory cache
func HasKey(id string, pub bool) bool {
	return ed25519Cache.Exists(id, pub)
}

// RemoveKey based on provided key id, removes a key from the cache
func RemoveKey(id string, pub bool) bool {
	return ed25519Cache.Exists(id, pub)
}
