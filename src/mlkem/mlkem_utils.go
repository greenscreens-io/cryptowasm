/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package mlkem

import (
	"crypto/mlkem"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"wasm/cryptowasm/src/lib"
)

// encodePrivKey encode GO private key into a Base64 PEM format
func encodePrivKey(privateKey DecapsulationKey) (string, error) {
	x509Encoded, err := encodePrivKeyRaw(privateKey)
	if err != nil {
		return "", err
	}
	return encodePrivKeyPEM(x509Encoded)
}

// encodePrivKeyRaw convert GO private key structure into a binary PKCS8 form
func encodePrivKeyRaw(privateKey DecapsulationKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

// encodePrivKeyPEM convert PKCS8 binary form into a Base64 format
func encodePrivKeyPEM(x509Encoded []byte) (string, error) {
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE ML KEY", Bytes: x509Encoded})
	return string(pemEncoded), nil
}

// encodePubKey encode GO public key into a Base64 PEM format
func encodePubKey(publicKey EncapsulationKey) (string, error) {
	x509EncodedPub, err := encodePubKeyRaw(publicKey)
	if err != nil {
		return "", err
	}
	return encodePubKeyPEM(x509EncodedPub)
}

// encodePubKeyRaw convert GO public key structure into a binary PKIX form
func encodePubKeyRaw(publicKey EncapsulationKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

// encodePubKeyPEM convert PKIX binary form into a Base64 format
func encodePubKeyPEM(x509EncodedPub []byte) (string, error) {
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC ML KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub), nil
}

// decodePrivKey decodes PKCS8 Base64 encoded private key into GO structure
func decodePrivKey(privateKey string) (DecapsulationKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	x509Encoded := block.Bytes
	return decodePrivKeyRaw(x509Encoded)
}

// decodePrivKeyRaw decodes PKCS8 binary encoded private key into GO structure
func decodePrivKeyRaw(x509Encoded []byte) (DecapsulationKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	return pk.(DecapsulationKey), nil
}

// decodePubKey decodes PKIX Base64 encoded public key into GO structure
func decodePubKey(publicKey string) (EncapsulationKey, error) {
	blockPub, _ := pem.Decode([]byte(publicKey))
	x509EncodedPub := blockPub.Bytes
	return decodePubKeyRaw(x509EncodedPub)
}

// decodePubKeyRaw decodes PKIX binary encoded public key into GO structure
func decodePubKeyRaw(x509EncodedPub []byte) (EncapsulationKey, error) {
	pk, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, err
	}
	return pk.(EncapsulationKey), nil
}

// exportPrivateJWK exports GO private key structure into JSON Web Token
func exportPrivateJWK(key DecapsulationKey) (jwk map[string]any, err error) {
	enc := base64.RawURLEncoding
	publicKey := key.EncapsulationKey()
	algo, err := toAlgo(publicKey)
	if err != nil {
		return nil, err
	}
	// TODO get encapsulate,decapsulate
	var ops []string
	jwk = map[string]any{
		"alg":     algo,
		"pub":     enc.EncodeToString(publicKey.Bytes()[0:]),
		"priv":    enc.EncodeToString(key.Bytes()[0:]),
		"key_ops": ops,
		"ext":     "true",
		"kty":     "KEM",
	}
	return jwk, nil
}

// exportPublicJWK exports GO public key structure into JSON Web Token
func exportPublicJWK(key EncapsulationKey) (jwk map[string]any, err error) {
	enc := base64.RawURLEncoding
	algo, err := toAlgo(key)
	if err != nil {
		return nil, err
	}
	// TODO get encapsulate,decapsulate
	var ops []string
	jwk = map[string]any{
		"alg":     algo,
		"pub":     enc.EncodeToString(key.Bytes()[0:]),
		"key_ops": ops,
		"ext":     "true",
		"kty":     "KEM",
	}
	return jwk, nil
}

func toAlgo(key EncapsulationKey) (string, error) {
	switch any(key).(type) {
	case *mlkem.EncapsulationKey768:
		return "ML-KEM-768", nil
	case *mlkem.EncapsulationKey1024:
		return "ML-KEM-1024", nil
	}
	return "", errors.New("Unknown ML-Key type")
}

// nameToCurve convert algorithm name to a curve function
func nameToSize(name string) (int, error) {
	switch name {
	case MLKEM512:
		return 512, nil
	case MLKEM768:
		return 768, nil
	case MLKEM1024:
		return 1024, nil
	default:
		return 0, errors.New(lib.ERR_INVALID_KEY_ML)
	}
}

func importRawPublicKey(size int, raw []byte) (EncapsulationKey, error) {

	var mlkey EncapsulationKey
	var err error

	switch size {
	case 768:
		mlkey, err = importRawPublic768(raw)
	case 1024:
		mlkey, err = importRawPublic1024(raw)
	}

	if err != nil {
		return nil, err
	}

	return mlkey, nil
}

func importRawPrivateKey(size int, raw []byte) (DecapsulationKey, error) {

	var mlkey DecapsulationKey
	var err error

	switch size {
	case 768:
		mlkey, err = importRawPrivate768(raw)
	case 1024:
		mlkey, err = importRawPrivate1024(raw)
	}

	if err != nil {
		return nil, err
	}

	return mlkey, nil
}

func importRawPrivate768(raw []byte) (DecapsulationKey, error) {
	k, err := mlkem.NewDecapsulationKey768(raw)
	if err != nil {
		return nil, err
	}
	return wrap768{k}, nil
}

func importRawPrivate1024(raw []byte) (DecapsulationKey, error) {
	k, err := mlkem.NewDecapsulationKey1024(raw)
	if err != nil {
		return nil, err
	}
	return wrap1024{k}, nil
}

func importRawPublic768(raw []byte) (EncapsulationKey, error) {
	k, err := mlkem.NewEncapsulationKey768(raw)
	if err != nil {
		return nil, err
	}
	return pubWrap768{k}, nil
}

func importRawPublic1024(raw []byte) (EncapsulationKey, error) {
	k, err := mlkem.NewEncapsulationKey1024(raw)
	if err != nil {
		return nil, err
	}
	return pubWrap1024{k}, nil
}

func generate768() (DecapsulationKey, error) {
	k, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return wrap768{k}, nil
}

func generate1024() (DecapsulationKey, error) {
	k, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	return wrap1024{k}, nil
}
