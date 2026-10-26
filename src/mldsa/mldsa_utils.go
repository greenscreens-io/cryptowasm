/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package mldsa

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func encodePrivKey(privateKey *mldsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})), nil
}

func decodePrivKey(privateKey string) (*mldsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("invalid ML-DSA private key PEM")
	}
	return decodePrivKeyRaw(block.Bytes)
}

func decodePrivKeyRaw(encoded []byte) (*mldsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, errors.New("PKCS8 key is not an ML-DSA private key")
	}
	return privateKey, nil
}

func encodePubKey(publicKey *mldsa.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})), nil
}

func decodePubKey(publicKey string) (*mldsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("invalid ML-DSA public key PEM")
	}
	return decodePubKeyRaw(block.Bytes)
}

func decodePubKeyRaw(encoded []byte) (*mldsa.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(*mldsa.PublicKey)
	if !ok {
		return nil, errors.New("PKIX key is not an ML-DSA public key")
	}
	return publicKey, nil
}

func exportPrivateJWK(key *mldsa.PrivateKey) (map[string]any, error) {
	name, err := nameForParameters(key.PublicKey().Parameters())
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	return map[string]any{
		"crv":     name,
		"pub":     enc.EncodeToString(key.PublicKey().Bytes()),
		"priv":    enc.EncodeToString(key.Bytes()),
		"key_ops": []string{"sign"},
		"ext":     true,
		"kty":     "ML-DSA",
	}, nil
}

func exportPublicJWK(key *mldsa.PublicKey) (map[string]any, error) {
	name, err := nameForParameters(key.Parameters())
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding
	return map[string]any{
		"crv":     name,
		"pub":     enc.EncodeToString(key.Bytes()),
		"key_ops": []string{"verify"},
		"ext":     true,
		"kty":     "ML-DSA",
	}, nil
}
