/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package mldsa

import (
	"crypto/mldsa"
	"errors"
	"fmt"
	"sync"
	"wasm/cryptowasm/src/lib"
)

var mldsaCache = lib.NewKeyStore[mldsa.PrivateKey]()
var mlpubCache = lib.NewKeyStore[mldsa.PublicKey]()
var keyCacheMu sync.RWMutex

var errInvalidParameters = errors.New("invalid ML-DSA parameter set (44, 65, 87) available")
var errRawPrivateKeyNeedsAlgorithm = errors.New("raw ML-DSA private key import requires an algorithm")

func parametersForSize(size int) (mldsa.Parameters, error) {
	switch size {
	case 44:
		return mldsa.MLDSA44(), nil
	case 65:
		return mldsa.MLDSA65(), nil
	case 87:
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, errInvalidParameters
	}
}

func parametersForName(name string) (mldsa.Parameters, error) {
	switch name {
	case MLDSA44:
		return mldsa.MLDSA44(), nil
	case MLDSA65:
		return mldsa.MLDSA65(), nil
	case MLDSA87:
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, fmt.Errorf("%w: %q", errInvalidParameters, name)
	}
}

func nameForParameters(params mldsa.Parameters) (string, error) {
	switch params {
	case mldsa.MLDSA44():
		return MLDSA44, nil
	case mldsa.MLDSA65():
		return MLDSA65, nil
	case mldsa.MLDSA87():
		return MLDSA87, nil
	default:
		return "", errInvalidParameters
	}
}

func ImportPrivateKey(data any, algorithm ...string) (string, error) {
	if len(algorithm) > 1 {
		return "", errors.New(lib.ERR_INVALID_ARGS)
	}

	var privateKey *mldsa.PrivateKey
	var err error

	switch value := data.(type) {
	case string:
		privateKey, err = decodePrivKey(value)
	case []byte:
		privateKey, err = decodePrivKeyRaw(value)
		if err != nil && len(value) == mldsa.PrivateKeySize && len(algorithm) == 0 {
			return "", errRawPrivateKeyNeedsAlgorithm
		}
		if err != nil && len(algorithm) > 0 && algorithm[0] != "" {
			var params mldsa.Parameters
			params, err = parametersForName(algorithm[0])
			if err == nil {
				privateKey, err = mldsa.NewPrivateKey(params, value)
			}
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
	if len(algorithm) > 0 && algorithm[0] != "" {
		params, err := parametersForName(algorithm[0])
		if err != nil {
			return "", err
		}
		if privateKey.PublicKey().Parameters() != params {
			return "", errors.New("ML-DSA algorithm does not match the imported private key")
		}
	}

	return storePrivateKey(privateKey), nil
}

func ImportPublicKey(data any) (string, error) {
	var publicKey *mldsa.PublicKey
	var err error

	switch value := data.(type) {
	case string:
		publicKey, err = decodePubKey(value)
	case []byte:
		raw := value
		publicKey, err = decodePubKeyRaw(raw)
		if err != nil {
			publicKey, err = importRawPublicKey(raw)
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

	return storePublicKey(publicKey), nil
}

func ImportJWK(raw *map[string][]byte, algorithm string) (string, error) {
	if raw == nil {
		return "", errors.New(lib.ERR_KEY_NOT_IMPORTED)
	}

	params, err := parametersForName(algorithm)
	if err != nil {
		return "", err
	}

	keys := *raw
	if len(keys["priv"]) > 0 {
		privateKey, err := mldsa.NewPrivateKey(params, keys["priv"])
		if err != nil {
			return "", err
		}
		if len(keys["pub"]) > 0 {
			publicKey, err := mldsa.NewPublicKey(params, keys["pub"])
			if err != nil {
				return "", err
			}
			if !privateKey.PublicKey().Equal(publicKey) {
				return "", errors.New("ML-DSA JWK public and private keys do not match")
			}
		}
		return storePrivateKey(privateKey), nil
	}

	publicKey, err := mldsa.NewPublicKey(params, keys["pub"])
	if err != nil {
		return "", err
	}
	return storePublicKey(publicKey), nil
}

func ExportPrivateKey(id string, format lib.Format) (any, error) {
	privateKey := getPrivateKey(id)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
	}

	switch format {
	case lib.FormatRaw:
		return privateKey.Bytes(), nil
	case lib.FormatPem:
		return encodePrivKey(privateKey)
	case lib.FormatJWK:
		return exportPrivateJWK(privateKey)
	default:
		return nil, errors.New(lib.ERR_INVALID_FORMAT)
	}
}

func ExportPublicKey(id string, format lib.Format) (any, error) {
	publicKey := getPublicKey(id)
	if publicKey == nil {
		privateKey := getPrivateKey(id)
		if privateKey == nil {
			return nil, errors.New(lib.ERR_KEY_NOT_FOUND)
		}
		publicKey = privateKey.PublicKey()
	}

	switch format {
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

func GenerateKey(size int) (string, error) {
	params, err := parametersForSize(size)
	if err != nil {
		return "", err
	}

	privateKey, err := mldsa.GenerateKey(params)
	if err != nil {
		return "", err
	}
	return storePrivateKey(privateKey), nil
}

func Sign(id string, data []byte, context ...string) ([]byte, error) {
	if len(context) > 1 {
		return nil, errors.New(lib.ERR_INVALID_ARGS)
	}
	privateKey := getPrivateKey(id)
	if privateKey == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_FOUND_PRV)
	}

	signingContext := ""
	if len(context) > 0 {
		signingContext = context[0]
	}
	if len(signingContext) > 255 {
		return nil, errors.New("ML-DSA context must be at most 255 bytes")
	}
	return privateKey.Sign(nil, data, &mldsa.Options{Context: signingContext})
}

func Verify(id string, data, signature []byte, context ...string) (bool, error) {
	if len(context) > 1 {
		return false, errors.New(lib.ERR_INVALID_ARGS)
	}
	publicKey := getPublicKey(id)
	if publicKey == nil {
		privateKey := getPrivateKey(id)
		if privateKey == nil {
			return false, errors.New(lib.ERR_KEY_NOT_FOUND_PUB)
		}
		publicKey = privateKey.PublicKey()
	}

	signingContext := ""
	if len(context) > 0 {
		signingContext = context[0]
	}
	if len(signingContext) > 255 {
		return false, errors.New("ML-DSA context must be at most 255 bytes")
	}
	err := mldsa.Verify(publicKey, data, signature, &mldsa.Options{Context: signingContext})
	return err == nil, nil
}

func HasKey(id string, pub bool) bool {
	keyCacheMu.RLock()
	defer keyCacheMu.RUnlock()
	if pub {
		return mlpubCache.Exist(id)
	}
	return mldsaCache.Exist(id)
}

func RemoveKey(id string, pub bool) bool {
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	if pub {
		return mlpubCache.Remove(id)
	}
	return mldsaCache.Remove(id)
}

func importRawPublicKey(raw []byte) (*mldsa.PublicKey, error) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		if len(raw) == params.PublicKeySize() {
			return mldsa.NewPublicKey(params, raw)
		}
	}
	return nil, errInvalidParameters
}

func storePrivateKey(key *mldsa.PrivateKey) string {
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	return mldsaCache.Set(lib.RandomStr(lib.IdSize), key)
}

func storePublicKey(key *mldsa.PublicKey) string {
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	return mlpubCache.Set(lib.RandomStr(lib.IdSize), key)
}

func getPrivateKey(id string) *mldsa.PrivateKey {
	keyCacheMu.RLock()
	defer keyCacheMu.RUnlock()
	return mldsaCache.Get(id)
}

func getPublicKey(id string) *mldsa.PublicKey {
	keyCacheMu.RLock()
	defer keyCacheMu.RUnlock()
	return mlpubCache.Get(id)
}
