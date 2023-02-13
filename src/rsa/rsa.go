/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"reflect"
	"wasm/cryptojs/src/base"
	"wasm/cryptojs/src/lib"
)

var stringType = reflect.TypeOf("")
var byteArrayType = reflect.TypeOf([]byte{})

var rsaCache = lib.NewKeyPairStore[rsa.PrivateKey, rsa.PublicKey]()

func ImportPrivateKey(data any) (string, error) {

	var privateKey *rsa.PrivateKey
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

	return rsaCache.SetKeyPair(privateKey, &privateKey.PublicKey), err
}

func ImportPublicKey(data any) (string, error) {

	var publicKey *rsa.PublicKey
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

	return rsaCache.SetKeyPair(nil, publicKey), err
}

func ImportJWK(raw *map[string][]byte) (string, error) {

	if len((*raw)["d"]) == 0 {
		k := importPublicJWK(raw)
		return rsaCache.SetKeyPair(nil, k), nil
	} else {
		k := importPrivateJWK(raw)
		return rsaCache.SetKeyPair(k, &k.PublicKey), nil
	}

}

func ExportPrivateKey(id string, fmt lib.Format) (any, error) {

	privateKey := rsaCache.Private.Get(id)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	var data any
	var err error

	switch fmt {
	case lib.FormatPem:
		data, err = encodePrivKey(privateKey)
	case lib.FormatJWK:
		data, err = exportPrivateJWK(privateKey)
	default:
		data, err = nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

	if err != nil {
		return nil, err
	}

	return data, nil
}

func ExportPublicKey(id string, fmt lib.Format) (any, error) {

	publicKey := rsaCache.Public.Get(id)
	if publicKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	var data any
	var err error

	switch fmt {
	case lib.FormatPem:
		data, err = encodePubKey(publicKey)
	case lib.FormatJWK:
		data, err = exportPublicJWK(publicKey)
	default:
		data, err = nil, errors.New(lib.ERR_INVALID_FORMAT)
	}

	if err != nil {
		return nil, err
	}

	return data, nil
}

func GenerateKey(size, publicExponent int) (string, error) {

	valid := size % 1024
	if valid != 0 {
		return "", errors.New(lib.ERR_INVALID_KEY_RSA)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return "", err
	}

	if publicExponent > 0 {
		privateKey.PublicKey.E = publicExponent
	}

	return rsaCache.SetKeyPair(privateKey, &privateKey.PublicKey), nil
}

func HasKey(id string, pub bool) bool {
	return rsaCache.Exists(id, pub)
}

func RemoveKey(id string, pub bool) bool {
	return rsaCache.Exists(id, pub)
}

func Encrypt(id string, size int, data []byte) ([]byte, error) {

	publicKey := rsaCache.Public.Get(id)
	if publicKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	alg, err := base.SizeToAlg(size)
	if err != nil {
		return nil, err
	}

	return rsa.EncryptOAEP(alg.New(), rand.Reader, publicKey, data, nil)
}

func Decrypt(id string, size int, data []byte) ([]byte, error) {

	privateKey := rsaCache.Private.Get(id)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	alg, err := base.SizeToAlg(size)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(alg.New(), rand.Reader, privateKey, data, nil)
}

/*
NOTE: saltLength not supported by GO due to the  PSSSaltLengthAuto = 0 (might be -2 etc.)
*/
func SignPSS(id string, data []byte, hashLength, saltLength int) ([]byte, error) {

	privateKey := rsaCache.Private.Get(id)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	if hashLength == 0 {
		return nil, errors.New(lib.ERR_INVALID_HASH)
	}

	hash := base.DataToHash(data, hashLength)

	alg, err := base.SizeToAlg(hashLength)
	if err != nil {
		return nil, err
	}

	opt := rsa.PSSOptions{SaltLength: saltLength, Hash: alg}
	return rsa.SignPSS(rand.Reader, privateKey, alg, hash, &opt)
}

func VerifyPSS(id string, data, signature []byte, hashLength, saltLength int) error {

	publicKey := rsaCache.Public.Get(id)
	if publicKey == nil {
		return errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	if hashLength == 0 {
		return errors.New(lib.ERR_INVALID_HASH)
	}

	hash := base.DataToHash(data, hashLength)

	alg, err := base.SizeToAlg(hashLength)
	if err != nil {
		return err
	}

	opt := rsa.PSSOptions{SaltLength: saltLength, Hash: alg}
	return rsa.VerifyPSS(publicKey, alg, hash, signature, &opt)
}

func SignPKCS1v15(id string, data []byte, size int) ([]byte, error) {

	privateKey := rsaCache.Private.Get(id)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	if size == 0 {
		return nil, errors.New(lib.ERR_INVALID_HASH)
	}

	hash := base.DataToHash(data, size)

	alg, err := base.SizeToAlg(size)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, privateKey, alg, hash)
}

func VerifyPKCS1v15(id string, data, signature []byte, size int) error {

	publicKey := rsaCache.Public.Get(id)
	if publicKey == nil {
		return errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	if size == 0 {
		return errors.New(lib.ERR_INVALID_HASH)
	}

	hash := base.DataToHash(data, size)

	alg, err := base.SizeToAlg(size)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(publicKey, alg, hash, signature)
}
