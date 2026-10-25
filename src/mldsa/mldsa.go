/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package mldsa

import (
	"encoding/base64"
	"errors"
	"reflect"
	"wasm/cryptowasm/src/lib"
)

var stringType = reflect.TypeOf("")
var byteArrayType = reflect.TypeOf([]byte{})

var mlkemCache = lib.NewKeyStore[any]()
var mlpubCache = lib.NewKeyStore[any]()

// ImportPrivateKey imports ECDH key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPrivateKey(data any) (string, error) {

	var privateKey any
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

	return mlkemCache.Set(lib.RandomStr(lib.IdSize), &privateKey), nil
}

// ImportPublicKey imports ML key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPublicKey(data any) (string, error) {

	var publicKey any
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

	return mlpubCache.Set(lib.RandomStr(lib.IdSize), &publicKey), nil
}

// ImportJWK imports JSON format of JSON Web Key into GO structure;
// returns an id of key stored in internal cache
func ImportJWK(raw *map[string][]byte, algo string) (string, error) {

	enc := base64.RawURLEncoding
	size, err := nameToSize(algo)
	if err != nil {
		return "", err
	}

	isPublic := len((*raw)["priv"]) == 0

	if isPublic {
		raw, err := enc.DecodeString(string((*raw)["pub"]))
		if err != nil {
			return "", err
		}

		k, err := importRawPublicKey(size, raw)
		if err != nil {
			return "", err
		}
		return mlpubCache.Set(lib.RandomStr(lib.IdSize), &k), nil
	} else {
		raw, err := enc.DecodeString(string((*raw)["priv"]))
		if err != nil {
			return "", err
		}
		k, err := importRawPrivateKey(size, raw)
		if err != nil {
			return "", err
		}
		return mlkemCache.Set(lib.RandomStr(lib.IdSize), &k), nil
	}

}

// ExportPrivateKey exports Go structure private key in one of supported formats (Binary,Base64,JWK)
// input is id of a key stored in intenal memory cache
func ExportPrivateKey(id string, fmt lib.Format) (any, error) {

	var mlkey *any
	mlkey = mlkemCache.Get(id)
	if mlkey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	switch fmt {
	case lib.FormatRaw:
		return (*mlkey).Bytes(), nil
	case lib.FormatPem:
		return encodePrivKey(*mlkey)
	case lib.FormatJWK:
		return exportPrivateJWK(*mlkey)
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

}

// ExportPublicKey exports Go structure public key in one of supported formats (Binary,Base64,JWK)
// input is id of a key stored in intenal memory cache
func ExportPublicKey(id string, fmt lib.Format) (any, error) {

	var mlkey *any
	mlkey = mlkemCache.Get(id)
	if mlkey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	switch fmt {
	case lib.FormatRaw:
		return (*mlkey).Bytes(), nil
	case lib.FormatPem:
		return encodePubKey((*mlkey))
	case lib.FormatJWK:
		return exportPublicJWK((*mlkey))
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

}

// GenerateKey randomly generates a keypair based on allowed size
// Allowed sizes are 512, 768, 1024
func GenerateKey(size int) (string, error) {

	var dsakey any
	var err error

	switch size {
	case 44:

	case 65:
		// dsakey, err := mldsa.GenerateKey65(rand.Reader)
	case 87:

	}

	if err != nil {
		return "", err
	}

	return mlkemCache.Set(lib.RandomStr(lib.IdSize), &dsakey), nil
}

func Sign(id string, data []byte) ([]byte, error) {
	var mlpkey *any
	var mlkey *any

	mlpkey = mlpubCache.Get(id)
	if mlpkey == nil {
		mlkey = mlkemCache.Get(id)
		if mlkey == nil {
			return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
		}
		pkey := (*mlkey).EncapsulationKey()
		mlpkey = &pkey
	}

	sharedSecret, cipherText := (*mlpkey).Encapsulate()
	return sharedSecret, cipherText, nil
}

func Verify(id string, data []byte) (bool, error) {
	var mlkey *any
	mlkey = mlkemCache.Get(id)
	if mlkey == nil {
		return false, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	// return sharedSecretRecovered, error
	return false, nil
}

// HasKey based on provided key id, checks if a key (public or private)
// exist in the memory cache
func HasKey(id string, pub bool) bool {
	if pub {
		return mlpubCache.Exist(id)
	}
	return mlkemCache.Exist(id)
}

// RemoveKey based on provided key id, removes a key from the cache
func RemoveKey(id string, pub bool) bool {
	if pub {
		return mlpubCache.Remove(id)
	}
	return mlkemCache.Remove(id)
}
