/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package ed25519

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// encodePrivKey encode GO private key into a Base64 PEM format
func encodePrivKey(privateKey *ed25519.PrivateKey) (string, error) {
	x509Encoded, err := encodePrivKeyRaw(privateKey)
	if err != nil {
		return "", err
	}
	return encodePrivKeyPEM(x509Encoded)
}

// encodePrivKeyRaw convert GO private key structure into a binary PKCS8 form
func encodePrivKeyRaw(privateKey *ed25519.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(privateKey)
}

// encodePrivKeyPEM convert PKCS8 binary form into a Base64 format
func encodePrivKeyPEM(x509Encoded []byte) (string, error) {
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE EC KEY", Bytes: x509Encoded})
	return string(pemEncoded), nil
}

// encodePubKey encode GO public key into a Base64 PEM format
func encodePubKey(publicKey *ed25519.PublicKey) (string, error) {
	x509EncodedPub, err := encodePubKeyRaw(publicKey)
	if err != nil {
		return "", err
	}
	return encodePubKeyPEM(x509EncodedPub)
}

// encodePubKeyRaw convert GO public key structure into a binary PKIX form
func encodePubKeyRaw(publicKey *ed25519.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

// encodePubKeyPEM convert PKIX binary form into a Base64 format
func encodePubKeyPEM(x509EncodedPub []byte) (string, error) {
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC EC KEY", Bytes: x509EncodedPub})
	return string(pemEncodedPub), nil
}

// decodePrivKey decodes PKCS8 Base64 encoded private key into GO structure
func decodePrivKey(privateKey string) (*ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	x509Encoded := block.Bytes
	return decodePrivKeyRaw(x509Encoded)
}

// decodePrivKeyRaw decodes PKCS8 binary encoded private key into GO structure
func decodePrivKeyRaw(x509Encoded []byte) (*ed25519.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	return pk.(*ed25519.PrivateKey), nil
}

// decodePubKey decodes PKIX Base64 encoded public key into GO structure
func decodePubKey(publicKey string) (*ed25519.PublicKey, error) {
	blockPub, _ := pem.Decode([]byte(publicKey))
	x509EncodedPub := blockPub.Bytes
	return decodePubKeyRaw(x509EncodedPub)
}

// decodePubKeyRaw decodes PKIX binary encoded public key into GO structure
func decodePubKeyRaw(x509EncodedPub []byte) (*ed25519.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	if err != nil {
		return nil, err
	}
	return pk.(*ed25519.PublicKey), nil
}

// exportPrivateJWK exports GO private key structure into JSON Web Token
// https://www.rfc-editor.org/rfc/rfc8037#appendix-A
func exportPrivateJWK(key *ed25519.PrivateKey) (jwk map[string]any, err error) {
	enc := base64.RawURLEncoding
	pub := key.Public().(ed25519.PublicKey)
	jwk = map[string]any{
		"crv": "Ed25519",
		"d":   enc.EncodeToString([]byte(*key)),
		"x":   enc.EncodeToString([]byte(pub)),
		"ext": "true",
		"kty": "OKP",
	}
	return jwk, nil
}

// exportPublicJWK exports GO public key structure into JSON Web Token
// https://www.rfc-editor.org/rfc/rfc8037#appendix-A
func exportPublicJWK(key *ed25519.PublicKey) (jwk map[string]any, err error) {
	enc := base64.RawURLEncoding
	jwk = map[string]any{
		"crv": "Ed25519",
		"x":   enc.EncodeToString([]byte(*key)),
		"ext": "true",
		"kty": "OKP",
	}
	return jwk, nil
}
