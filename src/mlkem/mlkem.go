/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package mlkem

import (
	"encoding/base64"
	"errors"
	"wasm/cryptowasm/src/lib"
)

var mlkemCache = lib.NewKeyStore[DecapsulationKey]()
var mlpubCache = lib.NewKeyStore[EncapsulationKey]()

// ImportPrivateKey imports ECDH key encoded as PEM Base64 or raw binary encoding
// returns an id of key stored in internal cache
func ImportPrivateKey(data any, algorithm ...string) (string, error) {
	if len(algorithm) > 1 {
		return "", errors.New(lib.ERR_INVALID_ARGS)
	}

	var privateKey DecapsulationKey
	var err error

	switch value := data.(type) {
	case string:
		privateKey, err = decodePrivKey(value)
	case []byte:
		privateKey, err = decodePrivKeyRaw(value)
		if err != nil && len(algorithm) > 0 && algorithm[0] != "" {
			size, sizeErr := nameToSize(algorithm[0])
			if sizeErr != nil {
				return "", sizeErr
			}
			privateKey, err = importRawPrivateKey(size, value)
		}
	default:
		return "", errors.New(lib.ERR_KEY_NOT_IMPORTED)
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

	var publicKey EncapsulationKey
	var err error

	switch value := data.(type) {
	case string:
		publicKey, err = decodePubKey(value)
	case []byte:
		publicKey, err = decodePubKeyRaw(value)
		if err != nil {
			publicKey, err = importRawPublicKeyAuto(value)
		}
	default:
		return "", errors.New(lib.ERR_KEY_NOT_IMPORTED)
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
	if raw == nil {
		return "", errors.New(lib.ERR_KEY_NOT_IMPORTED)
	}

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

func importRawPublicKeyAuto(raw []byte) (EncapsulationKey, error) {
	key, err := importRawPublicKey(768, raw)
	if err == nil {
		return key, nil
	}
	key, secondErr := importRawPublicKey(1024, raw)
	if secondErr == nil {
		return key, nil
	}
	return nil, secondErr
}

// ExportPrivateKey exports Go structure private key in one of supported formats (Binary,Base64,JWK)
// input is id of a key stored in intenal memory cache
func ExportPrivateKey(id string, fmt lib.Format) (any, error) {

	var mlkey *DecapsulationKey
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
	if privateKey := mlkemCache.Get(id); privateKey != nil {
		publicKey := (*privateKey).EncapsulationKey()
		return exportPublicKey(publicKey, fmt)
	}
	if publicKey := mlpubCache.Get(id); publicKey != nil {
		return exportPublicKey(*publicKey, fmt)
	}
	return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
}

func exportPublicKey(key EncapsulationKey, fmt lib.Format) (any, error) {
	switch fmt {
	case lib.FormatRaw:
		return key.Bytes(), nil
	case lib.FormatPem:
		return encodePubKey(key)
	case lib.FormatJWK:
		return exportPublicJWK(key)
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}
}

// GenerateKey randomly generates a keypair based on allowed size
// Allowed sizes are 768 and 1024
func GenerateKey(size int) (string, error) {

	var mlkey DecapsulationKey
	var err error

	switch size {
	case 768:
		mlkey, err = generate768()
	case 1024:
		mlkey, err = generate1024()
	default:
		return "", errors.New(lib.ERR_INVALID_KEY_ML)
	}

	if err != nil {
		return "", err
	}
	if mlkey == nil {
		return "", errors.New(lib.ERR_KEY_NOT_IMPORTED)
	}

	return mlkemCache.Set(lib.RandomStr(lib.IdSize), &mlkey), nil
}

func Encapsulate(id string) ([]byte, []byte, error) {
	var mlpkey *EncapsulationKey
	var mlkey *DecapsulationKey

	mlpkey = mlpubCache.Get(id)
	if mlpkey == nil {
		mlkey = mlkemCache.Get(id)
		if mlkey == nil {
			return nil, nil, errors.New(lib.ERR_KEY_NOT_FOUND)
		}
		pkey := (*mlkey).EncapsulationKey()
		mlpkey = &pkey
	}

	sharedSecret, cipherText := (*mlpkey).Encapsulate()
	return sharedSecret, cipherText, nil
}

func Decapsulate(id string, cipherText []byte) ([]byte, error) {
	var mlkey *DecapsulationKey
	mlkey = mlkemCache.Get(id)
	if mlkey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	// return sharedSecretRecovered, error
	return (*mlkey).Decapsulate(cipherText)
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
