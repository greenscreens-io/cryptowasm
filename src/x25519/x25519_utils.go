/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package x25519

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// encodePrivKey encode GO private key into a Base64 PEM format
func encodePrivKey(privateKey *ecdh.PrivateKey) (string, error) {
	x509Encoded, err := encodePrivKeyRaw(privateKey)
	if err != nil {
		return "", err
	}
	return encodePrivKeyPEM(x509Encoded)
}

// encodePrivKeyRaw convert GO private key structure into a binary PKCS8 form
func encodePrivKeyRaw(privateKey *ecdh.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

// encodePrivKeyPEM convert PKCS8 binary form into a Base64 format
func encodePrivKeyPEM(x509Encoded []byte) (string, error) {
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE EC KEY", Bytes: x509Encoded})
	return string(pemEncoded), nil
}

// encodePubKey encode GO public key into a Base64 PEM format
func encodePubKey(publicKey *ecdh.PublicKey) (string, error) {
	x509EncodedPub, err := encodePubKeyRaw(publicKey)
	if err != nil {
		return "", err
	}
	return encodePubKeyPEM(x509EncodedPub)
}

// encodePubKeyRaw convert GO public key structure into a binary PKIX form
func encodePubKeyRaw(publicKey *ecdh.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

// encodePubKeyPEM convert PKIX binary form into a Base64 format
func encodePubKeyPEM(x509EncodedPub []byte) (string, error) {
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC EC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub), nil
}

// decodePrivKey decodes PKCS8 Base64 encoded private key into GO structure
func decodePrivKey(privateKey string) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	x509Encoded := block.Bytes
	return decodePrivKeyRaw(x509Encoded)
}

// decodePrivKeyRaw decodes PKCS8 binary encoded private key into GO structure
func decodePrivKeyRaw(x509Encoded []byte) (*ecdh.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	return pk.(*ecdsa.PrivateKey).ECDH()
}

// decodePubKey decodes PKIX Base64 encoded public key into GO structure
func decodePubKey(publicKey string) (*ecdh.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(publicKey))
	x509EncodedPub := blockPub.Bytes
	return decodePubKeyRaw(x509EncodedPub)
}

// decodePubKeyRaw decodes PKIX binary encoded public key into GO structure
func decodePubKeyRaw(x509EncodedPub []byte) (*ecdh.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, err
	}
	return pk.(*ecdsa.PublicKey).ECDH()
}

// exportPrivateJWK exports GO private key structure into JSON Web Token
func exportPrivateJWK(key *ecdh.PrivateKey) (jwk map[string]any, err error) {
	enc := base64.RawURLEncoding
	publicKey := key.PublicKey()
	sb := key.Bytes()
	pb := publicKey.Bytes()[1:]
	seg := len(pb) / 2
	jwk = map[string]any{
		"crv": "X25519",
		"d":   enc.EncodeToString(sb),
		"x":   enc.EncodeToString(pb[0:seg]),
		"y":   enc.EncodeToString(pb[seg:]),
		"ext": "true",
		"kty": "OKP",
	}
	return jwk, nil
}

// exportPublicJWK exports GO public key structure into JSON Web Token
func exportPublicJWK(key *ecdh.PublicKey) (jwk map[string]any, err error) {
	enc := base64.RawURLEncoding
	pb := key.Bytes()[1:]
	seg := len(pb) / 2
	jwk = map[string]any{
		"crv": "X25519",
		"x":   enc.EncodeToString(pb[0:seg]),
		"y":   enc.EncodeToString(pb[seg:]),
		"ext": "true",
		"kty": "OKP",
	}
	return jwk, nil
}
