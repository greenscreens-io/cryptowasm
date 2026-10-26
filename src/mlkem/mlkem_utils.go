/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package mlkem

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"wasm/cryptowasm/src/lib"
)

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type privateKeyInfo struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

var (
	oidMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	oidMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
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
	algorithm, err := algorithmForKey(privateKey.EncapsulationKey())
	if err != nil {
		return nil, err
	}
	seed, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, Bytes: privateKey.Bytes()})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(privateKeyInfo{
		Version:    0,
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: algorithm},
		PrivateKey: seed,
	})
}

// encodePrivKeyPEM convert PKCS8 binary form into a Base64 format
func encodePrivKeyPEM(x509Encoded []byte) (string, error) {
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
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
	algorithm, err := algorithmForKey(publicKey)
	if err != nil {
		return nil, err
	}
	raw := publicKey.Bytes()
	return asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: algorithm},
		PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
}

// encodePubKeyPEM convert PKIX binary form into a Base64 format
func encodePubKeyPEM(x509EncodedPub []byte) (string, error) {
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub), nil
}

// decodePrivKey decodes PKCS8 Base64 encoded private key into GO structure
func decodePrivKey(privateKey string) (DecapsulationKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_IMPORTED)
	}
	x509Encoded := block.Bytes
	return decodePrivKeyRaw(x509Encoded)
}

// decodePrivKeyRaw decodes PKCS8 binary encoded private key into GO structure
func decodePrivKeyRaw(x509Encoded []byte) (DecapsulationKey, error) {
	var info privateKeyInfo
	rest, err := asn1.Unmarshal(x509Encoded, &info)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || info.Version != 0 {
		return nil, errors.New("Invalid ML-KEM PKCS8 private key")
	}
	if len(info.Algorithm.Parameters.FullBytes) != 0 {
		return nil, errors.New("ML-KEM AlgorithmIdentifier parameters must be absent")
	}
	size, err := sizeForOID(info.Algorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	var seed asn1.RawValue
	rest, err = asn1.Unmarshal(info.PrivateKey, &seed)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || seed.Class != 2 || seed.Tag != 0 || seed.IsCompound {
		return nil, errors.New("Invalid ML-KEM private key seed")
	}
	return importRawPrivateKey(size, seed.Bytes)
}

// decodePubKey decodes PKIX Base64 encoded public key into GO structure
func decodePubKey(publicKey string) (EncapsulationKey, error) {
	blockPub, _ := pem.Decode([]byte(publicKey))
	if blockPub == nil {
		return nil, errors.New(lib.ERR_KEY_NOT_IMPORTED)
	}
	x509EncodedPub := blockPub.Bytes
	return decodePubKeyRaw(x509EncodedPub)
}

// decodePubKeyRaw decodes PKIX binary encoded public key into GO structure
func decodePubKeyRaw(x509EncodedPub []byte) (EncapsulationKey, error) {
	var info subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(x509EncodedPub, &info)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || info.PublicKey.BitLength != len(info.PublicKey.Bytes)*8 {
		return nil, errors.New("Invalid ML-KEM PKIX public key")
	}
	if len(info.Algorithm.Parameters.FullBytes) != 0 {
		return nil, errors.New("ML-KEM AlgorithmIdentifier parameters must be absent")
	}
	size, err := sizeForOID(info.Algorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	return importRawPublicKey(size, info.PublicKey.Bytes)
}

func algorithmForKey(key EncapsulationKey) (asn1.ObjectIdentifier, error) {
	switch any(key).(type) {
	case pubWrap768, *mlkem.EncapsulationKey768:
		return oidMLKEM768, nil
	case pubWrap1024, *mlkem.EncapsulationKey1024:
		return oidMLKEM1024, nil
	default:
		return nil, errors.New("Unknown ML-KEM key type")
	}
}

func sizeForOID(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidMLKEM768):
		return 768, nil
	case oid.Equal(oidMLKEM1024):
		return 1024, nil
	default:
		return 0, errors.New("Unsupported ML-KEM algorithm identifier")
	}
}

// exportPrivateJWK exports GO private key structure into JSON Web Token
func exportPrivateJWK(key DecapsulationKey) (jwk map[string]any, err error) {
	enc := base64.RawURLEncoding
	publicKey := key.EncapsulationKey()
	algo, err := toAlgo(publicKey)
	if err != nil {
		return nil, err
	}
	ops := []any{}
	jwk = map[string]any{
		"alg":     algo,
		"pub":     enc.EncodeToString(publicKey.Bytes()),
		"priv":    enc.EncodeToString(key.Bytes()),
		"key_ops": ops,
		"ext":     true,
		"kty":     "AKP",
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
	ops := []any{}
	jwk = map[string]any{
		"alg":     algo,
		"pub":     enc.EncodeToString(key.Bytes()),
		"key_ops": ops,
		"ext":     true,
		"kty":     "AKP",
	}
	return jwk, nil
}

func toAlgo(key EncapsulationKey) (string, error) {
	switch any(key).(type) {
	case pubWrap768, *mlkem.EncapsulationKey768:
		return "ML-KEM-768", nil
	case pubWrap1024, *mlkem.EncapsulationKey1024:
		return "ML-KEM-1024", nil
	}
	return "", errors.New("Unknown ML-Key type")
}

// nameToCurve convert algorithm name to a curve function
func nameToSize(name string) (int, error) {
	switch name {
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
	default:
		return nil, errors.New(lib.ERR_INVALID_KEY_ML)
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
	default:
		return nil, errors.New(lib.ERR_INVALID_KEY_ML)
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
