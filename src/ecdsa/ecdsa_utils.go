/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"runtime"
	"strconv"
	"wasm/cryptowasm/src/lib"
)

// encodePrivKey encode GO private key into a Base64 PEM format
func encodePrivKey(privateKey *ecdsa.PrivateKey) (string, error) {
	x509Encoded, err := encodePrivKeyRaw(privateKey)
	if err != nil {
		return "", err
	}
	return encodePrivKeyPEM(x509Encoded)
}

// encodePrivKeyRaw convert GO private key structure into a binary PKCS8 form
func encodePrivKeyRaw(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

// encodePrivKeyPEM convert PKCS8 binary form into a Base64 format
func encodePrivKeyPEM(x509Encoded []byte) (string, error) {
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE EC KEY", Bytes: x509Encoded})
	return string(pemEncoded), nil
}

// encodePubKey encode GO public key into a Base64 PEM format
func encodePubKey(publicKey *ecdsa.PublicKey) (string, error) {
	x509EncodedPub, err := encodePubKeyRaw(publicKey)
	if err != nil {
		return "", err
	}
	return encodePubKeyPEM(x509EncodedPub)
}

// encodePubKeyRaw convert GO public key structure into a binary PKIX form
func encodePubKeyRaw(publicKey *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

// encodePubKeyPEM convert PKIX binary form into a Base64 format
func encodePubKeyPEM(x509EncodedPub []byte) (string, error) {
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC EC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub), nil
}

// decodePrivKey decodes PKCS8 Base64 encoded private key into GO structure
func decodePrivKey(privateKey string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	x509Encoded := block.Bytes
	return decodePrivKeyRaw(x509Encoded)
}

// decodePrivKeyRaw decodes PKCS8 binary encoded private key into GO structure
func decodePrivKeyRaw(x509Encoded []byte) (*ecdsa.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	return pk.(*ecdsa.PrivateKey), nil
}

// decodePubKey decodes PKIX Base64 encoded public key into GO structure
func decodePubKey(publicKey string) (*ecdsa.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(publicKey))
	x509EncodedPub := blockPub.Bytes
	return decodePubKeyRaw(x509EncodedPub)
}

// decodePubKeyRaw decodes PKIX binary encoded public key into GO structure
func decodePubKeyRaw(x509EncodedPub []byte) (*ecdsa.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, err
	}
	return pk.(*ecdsa.PublicKey), nil
}

// importPrivateJWK imports JSON Web Token into GO private key structure
func importPrivateJWK(raw *map[string][]byte, curve string) (*ecdsa.PrivateKey, error) {

	fn, err := nameToCurve(curve)
	if err != nil {
		return nil, err
	}

	data := *raw
	k := ecdsa.PrivateKey{}
	k.Curve = fn
	k.D = big.NewInt(0).SetBytes(data["d"])
	k.X = big.NewInt(0).SetBytes(data["x"])
	k.Y = big.NewInt(0).SetBytes(data["y"])
	k.PublicKey = ecdsa.PublicKey{}
	k.PublicKey.X = k.X
	k.PublicKey.Y = k.Y
	k.PublicKey.Curve = fn

	runtime.KeepAlive(k)

	return &k, nil
}

// importPublicJWK imports JSON Web Token into GO public key structure
func importPublicJWK(raw *map[string][]byte, curve string) (*ecdsa.PublicKey, error) {

	fn, err := nameToCurve(curve)
	if err != nil {
		return nil, err
	}

	data := *raw
	k := ecdsa.PublicKey{}
	k.X = big.NewInt(0).SetBytes(data["x"])
	k.Y = big.NewInt(0).SetBytes(data["y"])
	k.Curve = fn

	runtime.KeepAlive(k)

	return &k, nil
}

// exportPrivateJWK exports GO private key structure into JSON Web Token
func exportPrivateJWK(key *ecdsa.PrivateKey) (jwk map[string]interface{}, err error) {
	enc := base64.RawURLEncoding
	s := strconv.Itoa(key.Curve.Params().BitSize)
	jwk = map[string]interface{}{
		"crv": "P-" + s,
		"d":   enc.EncodeToString(key.D.Bytes()),
		"x":   enc.EncodeToString(key.X.Bytes()),
		"y":   enc.EncodeToString(key.Y.Bytes()),
		"ext": "true",
		"kty": "EC",
	}
	return jwk, nil
}

// exportPublicJWK exports GO public key structure into JSON Web Token
func exportPublicJWK(key *ecdsa.PublicKey) (jwk map[string]interface{}, err error) {
	enc := base64.RawURLEncoding
	s := strconv.Itoa(key.Curve.Params().BitSize)
	jwk = map[string]interface{}{
		"crv": "P-" + s,
		"x":   enc.EncodeToString(key.X.Bytes()),
		"y":   enc.EncodeToString(key.Y.Bytes()),
		"ext": "true",
		"kty": "EC",
	}
	return jwk, nil
}

// sizeToCurve converts bit size to Curve function
func sizeToCurve(size int) (elliptic.Curve, error) {

	var curve elliptic.Curve

	switch size {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, errors.New(lib.ERR_INVALID_KEY_EC)
	}

	return curve, nil
}

// nameToCurve convert algorithm name to a curve function
func nameToCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, errors.New(lib.ERR_INVALID_KEY_EC)
	}
}

func toRaw(rb, sb []byte, size int) []byte {

	if size%8 > 0 {
		size = size + (8 - (size % 8))
	}

	keyLen := int(math.Max(float64(len(rb)), float64(len(sb))))
	if keyLen*8 < size {
		keyLen = int(size / 8)
	}

	raw := make([]byte, keyLen*2)
	boff := keyLen - len(rb)
	soff := keyLen - len(sb)
	copy(raw[boff:], rb)
	copy(raw[keyLen+soff:], sb)
	return raw
}

func fromRaw(signature []byte) (r, s *big.Int) {
	r = big.NewInt(0)
	s = big.NewInt(0)
	keyLen := int(len(signature) / 2)
	r.SetBytes(signature[0:keyLen])
	s.SetBytes(signature[keyLen:])
	return r, s
}
