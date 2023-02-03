//go:build windows

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package main

import (
	"C"
	"encoding/base64"
	"wasm/cryptojs/src/base"
	"wasm/cryptojs/src/ecdh"
	"wasm/cryptojs/src/ecdsa"
	"wasm/cryptojs/src/ed25519"
	"wasm/cryptojs/src/lib"
	"wasm/cryptojs/src/rsa"
)

/*
 * Module for creating MS Windows DLL, not related to WASM build
 */

var lastError error

//export GetError
func GetError() string {
	if lastError == nil {
		return ""
	}
	msg := lastError.Error()
	lastError = nil
	return msg
}

//export Random
func Random(size int) []byte {
	data, err := base.Random(size)
	lastError = err
	return data
}

//export MD5
func MD5(data []byte) []byte {
	data, err := base.MD5(data)
	lastError = err
	return data
}

//export Sha_1
func Sha_1(data []byte) []byte {
	data, err := base.Sha1(data)
	lastError = err
	return data
}

//export Sha_224
func Sha_224(data []byte) []byte {
	data, err := base.Sha224(data)
	lastError = err
	return data
}

//export Sha_256
func Sha_256(data []byte) []byte {
	data, err := base.Sha256(data)
	lastError = err
	return data
}

//export Sha_384
func Sha_384(data []byte) []byte {
	data, err := base.Sha384(data)
	lastError = err
	return data
}

//export Sha_512
func Sha_512(data []byte) []byte {
	data, err := base.Sha512(data)
	lastError = err
	return data
}

//export Hmac_1_Sign
func Hmac_1_Sign(data, key []byte) []byte {
	return base.Hmac1Sign(data, key)
}

//export Hmac_256_Sign
func Hmac_256_Sign(data, key []byte) []byte {
	return base.Hmac256Sign(data, key)
}

//export Hmac_384_Sign
func Hmac_384_Sign(data, key []byte) []byte {
	return base.Hmac384Sign(data, key)
}

//export Hmac_512_Sign
func Hmac_512_Sign(data, key []byte) []byte {
	return base.Hmac512Sign(data, key)
}

//export Hmac_1_Verify
func Hmac_1_Verify(data, mac, key []byte) bool {
	return base.Hmac1Verify(data, mac, key)
}

//export Hmac_256_Verify
func Hmac_256_Verify(data, mac, key []byte) bool {
	return base.Hmac256Verify(data, mac, key)
}

//export Hmac_384_Verify
func Hmac_384_Verify(data, mac, key []byte) bool {
	return base.Hmac384Verify(data, mac, key)
}

//export Hmac_512_Verify
func Hmac_512_Verify(data, mac, key []byte) bool {
	return base.Hmac512Verify(data, mac, key)
}

//export HKDF_Generate_Key
func HKDF_Generate_Key(secret, salt, info []byte, size int) []byte {
	data, err := base.GenerateHKDF(secret, salt, info, size)
	lastError = err
	return data
}

//export PBKDF2_Generate_Key
func PBKDF2_Generate_Key(secret, salt []byte, iter, keyLen, hashLen int) []byte {
	data, err := base.GeneratePBKDF2(secret, salt, iter, keyLen, hashLen)
	lastError = err
	return data
}

//export RSA_Decrypt
func RSA_Decrypt(id string, size int, data []byte) []byte {
	data, err := rsa.Decrypt(id, size, data)
	lastError = err
	return data
}

//export RSA_Encrypt
func RSA_Encrypt(id string, size int, data []byte) []byte {
	data, err := rsa.Encrypt(id, size, data)
	lastError = err
	return data
}

//export RSA_Export_Private_Key_Raw
func RSA_Export_Private_Key_Raw(id string) []byte {
	data, err := rsa.ExportPrivateKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export RSA_Export_Private_Key_Pem
func RSA_Export_Private_Key_Pem(id string) string {
	data, err := rsa.ExportPrivateKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export RSA_Export_Private_Key_JWK
func RSA_Export_Private_Key_JWK(id string) map[string]string {
	data, err := rsa.ExportPrivateKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export RSA_Export_Public_Key_Raw
func RSA_Export_Public_Key_Raw(id string) []byte {
	data, err := rsa.ExportPublicKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export RSA_Export_Public_Key_Pem
func RSA_Export_Public_Key_Pem(id string) string {
	data, err := rsa.ExportPublicKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export RSA_Export_Public_Key_JWK
func RSA_Export_Public_Key_JWK(id string) map[string]string {
	data, err := rsa.ExportPublicKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export RSA_Generate_Key
func RSA_Generate_Key(size, publicExponent int) string {
	data, err := rsa.GenerateKey(size, publicExponent)
	lastError = err
	return data
}

//export RSA_Has_Key
func RSA_Has_Key(id string, pub bool) bool {
	return rsa.HasKey(id, pub)
}

//export RSA_Import_JWK
func RSA_Import_JWK(jsObj *map[string]string) string {

	keys := []string{"e", "n", "d", "p", "q", "qi", "dp", "dq"}
	jsRaw, err := decodeJWK(jsObj, keys)
	if err != nil {
		lastError = err
		return ""
	}

	data, err := rsa.ImportJWK(jsRaw)
	lastError = err
	return data
}

//export RSA_Import_Private_Key
func RSA_Import_Private_Key(raw []byte) string {
	data, err := rsa.ImportPrivateKey(raw)
	lastError = err
	return data
}

//export RSA_Import_Public_Key
func RSA_Import_Public_Key(raw []byte) string {
	data, err := rsa.ImportPublicKey(raw)
	lastError = err
	return data
}

//export RSA_Remove_Key
func RSA_Remove_Key(id string, pub bool) bool {
	return rsa.RemoveKey(id, pub)
}

//export RSA_Sign_PKCS_1v15
func RSA_Sign_PKCS_1v15(id string, raw []byte, size int) []byte {
	data, err := rsa.SignPKCS1v15(id, raw, size)
	lastError = err
	return data
}

//export RSA_Sign_PSS
func RSA_Sign_PSS(id string, raw []byte, hashLength, saltLength int) []byte {
	data, err := rsa.SignPSS(id, raw, hashLength, saltLength)
	lastError = err
	return data
}

//export RSA_Verify_PKCS_1v15
func RSA_Verify_PKCS_1v15(id string, data, signature []byte, size int) bool {
	err := rsa.VerifyPKCS1v15(id, data, signature, size)
	lastError = err
	return err != nil
}

//export RSA_Verify_PSS
func RSA_Verify_PSS(id string, data, signature []byte, hashLength, saltLength int) bool {
	err := rsa.VerifyPSS(id, data, signature, hashLength, saltLength)
	lastError = err
	return err != nil
}

//export ECDH_Remove_Key
func ECDH_Remove_Key(id string, pub bool) bool {
	return ecdh.RemoveKey(id, pub)
}

//export ECDH_Import_Public_Key
func ECDH_Import_Public_Key(raw []byte) string {
	data, err := ecdh.ImportPublicKey(raw)
	lastError = err
	return data
}

//export ECDH_Import_Private_Key
func ECDH_Import_Private_Key(raw []byte) string {
	data, err := ecdh.ImportPrivateKey(raw)
	lastError = err
	return data
}

//export ECDH_Import_JWK
func ECDH_Import_JWK(jsObj *map[string]string, curve string) string {

	keys := []string{"d", "x", "y"}
	jsRaw, err := decodeJWK(jsObj, keys)
	if err != nil {
		lastError = err
		return ""
	}

	data, err := ecdh.ImportJWK(jsRaw, curve)
	lastError = err
	return data
}

//export ECDH_Has_Key
func ECDH_Has_Key(id string, pub bool) bool {
	return ecdh.HasKey(id, pub)
}

//export ECDH_Generate_Key
func ECDH_Generate_Key(size int) string {
	data, err := ecdh.GenerateKey(size)
	lastError = err
	return data
}

//export ECDH_Export_Public_Key_Raw
func ECDH_Export_Public_Key_Raw(id string) []byte {
	data, err := ecdh.ExportPublicKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export ECDH_Export_Public_Key_Pem
func ECDH_Export_Public_Key_Pem(id string) string {
	data, err := ecdh.ExportPublicKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export ECDH_Export_Public_Key_JWK
func ECDH_Export_Public_Key_JWK(id string) map[string]string {
	data, err := ecdh.ExportPublicKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export ECDH_Export_Private_Key_Raw
func ECDH_Export_Private_Key_Raw(id string) []byte {
	data, err := ecdh.ExportPrivateKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export ECDH_Export_Private_Key_Pem
func ECDH_Export_Private_Key_Pem(id string) string {
	data, err := ecdh.ExportPrivateKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export ECDH_Export_Private_Key_JWK
func ECDH_Export_Private_Key_JWK(id string) map[string]string {
	data, err := ecdh.ExportPrivateKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export ECDH_Derive_Key
func ECDH_Derive_Key(priv, pub string, bitLen int) []byte {
	data, err := ecdh.DeriveKey(priv, pub, bitLen)
	lastError = err
	return data
}

//export ECDSA_Verify
func ECDSA_Verify(id string, data, signature []byte, size int, asn bool) bool {
	return ecdsa.Verify(id, data, signature, size, asn)
}

//export ECDSA_Sign
func ECDSA_Sign(id string, data []byte, size int, asn bool) []byte {
	data, err := ecdsa.Sign(id, data, size, asn)
	lastError = err
	return data
}

//export ECDSA_Remove_Key
func ECDSA_Remove_Key(id string, pub bool) bool {
	return ecdsa.RemoveKey(id, pub)
}

//export ECDSA_Import_Public_Key
func ECDSA_Import_Public_Key(raw []byte) string {
	data, err := ecdsa.ImportPublicKey(raw)
	lastError = err
	return data
}

//export ECDSA_Import_Private_Key
func ECDSA_Import_Private_Key(raw []byte) string {
	data, err := ecdsa.ImportPrivateKey(raw)
	lastError = err
	return data
}

//export ECDSA_Import_JWK
func ECDSA_Import_JWK(jsObj *map[string]string, curve string) string {

	keys := []string{"d", "x", "y"}
	jsRaw, err := decodeJWK(jsObj, keys)
	if err != nil {
		lastError = err
		return ""
	}

	data, err := ecdsa.ImportJWK(jsRaw, curve)
	lastError = err
	return data
}

//export ECDSA_Has_Key
func ECDSA_Has_Key(id string, pub bool) bool {
	return ecdsa.HasKey(id, pub)
}

//export ECDSA_Generate_Key
func ECDSA_Generate_Key(size int) string {
	data, err := ecdsa.GenerateKey(size)
	lastError = err
	return data
}

//export ECDSA_Export_Public_Key_Raw
func ECDSA_Export_Public_Key_Raw(id string) []byte {
	data, err := ecdsa.ExportPublicKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export ECDSA_Export_Public_Key_Pem
func ECDSA_Export_Public_Key_Pem(id string) string {
	data, err := ecdsa.ExportPublicKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export ECDSA_Export_Public_Key_JWK
func ECDSA_Export_Public_Key_JWK(id string) map[string]string {
	data, err := ecdsa.ExportPublicKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export ECDSA_Export_Private_Key_Raw
func ECDSA_Export_Private_Key_Raw(id string) []byte {
	data, err := ecdsa.ExportPrivateKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export ECDSA_Export_Private_Key_Pem
func ECDSA_Export_Private_Key_Pem(id string) string {
	data, err := ecdsa.ExportPrivateKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export ECDSA_Export_Private_Key_JWK
func ECDSA_Export_Private_Key_JWK(id string) map[string]string {
	data, err := ecdsa.ExportPrivateKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export ED25519_Verify
func ED25519_Verify(pub string, message, signature []byte, asn bool) bool {
	data, err := ed25519.Verify(pub, message, signature, asn)
	lastError = err
	return data
}

//export ED25519_Sign
func ED25519_Sign(priv string, message []byte, asn bool) []byte {
	data, err := ed25519.Sign(priv, message, asn)
	lastError = err
	return data
}

//export ED25519_Remove_Key
func ED25519_Remove_Key(id string, pub bool) bool {
	return ed25519.RemoveKey(id, pub)
}

//export ED25519_ImportPublic_Key
func ED25519_ImportPublic_Key(raw []byte) string {
	data, err := ed25519.ImportPublicKey(raw)
	lastError = err
	return data
}

//export ED25519_ImportPrivate_Key
func ED25519_ImportPrivate_Key(raw []byte) string {
	data, err := ed25519.ImportPrivateKey(raw)
	lastError = err
	return data
}

//export ED25519_Import_JWK
func ED25519_Import_JWK(jsObj *map[string]string) string {

	keys := []string{"d", "x"}
	jsRaw, err := decodeJWK(jsObj, keys)
	if err != nil {
		lastError = err
		return ""
	}

	data, err := ed25519.ImportJWK(jsRaw)
	lastError = err
	return data
}

//export ED25519_Has_Key
func ED25519_Has_Key(id string, pub bool) bool {
	return ed25519.HasKey(id, pub)
}

//export ED25519_Generate_Key
func ED25519_Generate_Key() string {
	data, err := ed25519.GenerateKey()
	lastError = err
	return data
}

//export ED25519_Export_Public_Key_Raw
func ED25519_Export_Public_Key_Raw(id string) []byte {
	data, err := ed25519.ExportPublicKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export ED25519_Export_Public_Key_Pem
func ED25519_Export_Public_Key_Pem(id string) string {
	data, err := ed25519.ExportPublicKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export ED25519_Export_Public_Key_JWK
func ED25519_Export_Public_Key_JWK(id string) map[string]string {
	data, err := ed25519.ExportPublicKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export ED25519_Export_Private_Key_Raw
func ED25519_Export_Private_Key_Raw(id string) []byte {
	data, err := ed25519.ExportPrivateKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export ED25519_Export_Private_Key_Pem
func ED25519_Export_Private_Key_Pem(id string) string {
	data, err := ed25519.ExportPrivateKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export ED25519_Export_Private_Key_JWK
func ED25519_Export_Private_Key_JWK(id string) map[string]string {
	data, err := ed25519.ExportPrivateKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

func decodeJWK(jsObj *map[string]string, keys []string) (*map[string][]byte, error) {

	jsRaw := map[string][]byte{}

	for _, v := range keys {
		err := decodeB64(v, jsObj, &jsRaw)
		if err != nil {
			return nil, err
		}
	}

	return &jsRaw, nil
}

func decodeB64(key string, jsObj *map[string]string, data *map[string][]byte) error {

	val := (*jsObj)[key]

	v, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil {
		return err
	}

	(*data)[key] = v

	return nil
}

func main() {

}
