/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"runtime"
)

// encodePrivKey encode GO private key into a Base64 PEM format
func encodePrivKey(privateKey *rsa.PrivateKey) (string, error) {
	x509Encoded, err := encodePrivKeyRaw(privateKey)
	if err != nil {
		return "", err
	}
	return encodePrivKeyPEM(x509Encoded)
}

// encodePrivKeyRaw convert GO private key structure into a binary PKCS8 form
func encodePrivKeyRaw(privateKey *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

// encodePrivKeyPEM convert PKCS8 binary form into a Base64 format
func encodePrivKeyPEM(x509Encoded []byte) (string, error) {
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE RSA KEY", Bytes: x509Encoded})
	return string(pemEncoded), nil
}

// encodePubKey encode GO public key into a Base64 PEM format
func encodePubKey(publicKey *rsa.PublicKey) (string, error) {
	x509EncodedPub, err := encodePubKeyRaw(publicKey)
	if err != nil {
		return "", err
	}
	return encodePubKeyPEM(x509EncodedPub)
}

// encodePubKeyRaw convert GO public key structure into a binary PKIX form
func encodePubKeyRaw(publicKey *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

// encodePubKeyPEM convert PKIX binary form into a Base64 format
func encodePubKeyPEM(x509EncodedPub []byte) (string, error) {
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC RSA KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub), nil
}

// decodePrivKey decodes PKCS8 Base64 encoded private key into GO structure
func decodePrivKey(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	x509Encoded := block.Bytes
	return decodePrivKeyRaw(x509Encoded)
}

// decodePrivKeyRaw decodes PKCS8 binary encoded private key into GO structure
func decodePrivKeyRaw(x509Encoded []byte) (*rsa.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	return pk.(*rsa.PrivateKey), nil
}

// decodePubKey decodes PKIX Base64 encoded public key into GO structure
func decodePubKey(publicKey string) (*rsa.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(publicKey))
	x509EncodedPub := blockPub.Bytes
	return decodePubKeyRaw(x509EncodedPub)
}

// decodePubKeyRaw decodes PKIX binary encoded public key into GO structure
func decodePubKeyRaw(x509EncodedPub []byte) (*rsa.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, err
	}
	return pk.(*rsa.PublicKey), nil
}

// importPrivateJWK imports JSON Web Token into GO private key structure
func importPrivateJWK(raw *map[string][]byte) *rsa.PrivateKey {

	data := *raw

	k := rsa.PrivateKey{}
	k.E = bytesToNumber(data["e"])
	k.N = big.NewInt(0).SetBytes(data["n"])
	k.D = big.NewInt(0).SetBytes(data["d"])

	k.Precomputed.Qinv = big.NewInt(0).SetBytes(data["qi"])
	k.Precomputed.Dp = big.NewInt(0).SetBytes(data["dp"])
	k.Precomputed.Dq = big.NewInt(0).SetBytes(data["dq"])

	k.Primes = []*big.Int{
		big.NewInt(0).SetBytes(data["p"]),
		big.NewInt(0).SetBytes(data["q"]),
	}

	p := importPublicJWK(raw)
	k.PublicKey = *p

	runtime.KeepAlive(k)
	return &k
}

// importPublicJWK imports JSON Web Token into GO public key structure
func importPublicJWK(raw *map[string][]byte) *rsa.PublicKey {

	data := *raw

	k := rsa.PublicKey{}
	k.E = bytesToNumber(data["e"])
	k.N = big.NewInt(0).SetBytes(data["n"])

	runtime.KeepAlive(k)
	return &k
}

// exportPrivateJWK exports GO private key structure into JSON Web Token
func exportPrivateJWK(key *rsa.PrivateKey) (jwk map[string]interface{}, err error) {
	enc := base64.RawURLEncoding
	exp := numberToBytes(uint32(key.E))
	jwk = map[string]interface{}{
		"e":   enc.EncodeToString(exp),
		"d":   enc.EncodeToString(key.D.Bytes()),
		"n":   enc.EncodeToString(key.N.Bytes()),
		"qi":  enc.EncodeToString(key.Precomputed.Qinv.Bytes()),
		"dp":  enc.EncodeToString(key.Precomputed.Dp.Bytes()),
		"dq":  enc.EncodeToString(key.Precomputed.Dq.Bytes()),
		"p":   enc.EncodeToString(key.Primes[0].Bytes()),
		"q":   enc.EncodeToString(key.Primes[1].Bytes()),
		"ext": "true",
		"kty": "RSA",
	}
	return jwk, nil
}

// exportPublicJWK exports GO public key structure into JSON Web Token
func exportPublicJWK(key *rsa.PublicKey) (jwk map[string]interface{}, err error) {
	enc := base64.RawURLEncoding
	exp := numberToBytes(uint32(key.E))
	jwk = map[string]interface{}{
		"e":   enc.EncodeToString(exp),
		"n":   enc.EncodeToString(key.N.Bytes()),
		"ext": "true",
		"kty": "RSA",
	}
	return jwk, nil
}

// numberToBytes internal helper function for converting between GO and non GO formats
func numberToBytes(v uint32) []byte {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, v)
	if bs[0] == 0 {
		return bs[1:]
	}
	return bs
}

// bytesToNumber internal helper function for converting between GO and non GO formats
func bytesToNumber(v []byte) int {
	l := len(v)
	if l < 4 {
		f := make([]byte, 4-l)
		return int(binary.BigEndian.Uint32(append(f, v...)))
	}
	return int(binary.BigEndian.Uint32(v))
}
