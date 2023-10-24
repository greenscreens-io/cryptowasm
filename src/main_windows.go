//go:build windows

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package main

// #include <stdlib.h>
import "C"
import (
	"encoding/base64"
	"unsafe"
	"wasm/cryptowasm/src/base"
	"wasm/cryptowasm/src/ecdh"
	"wasm/cryptowasm/src/ecdsa"
	"wasm/cryptowasm/src/ed25519"
	"wasm/cryptowasm/src/lib"
	"wasm/cryptowasm/src/rsa"
	"wasm/cryptowasm/src/x25519"
)

/*
 * Module for creating MS Windows DLL, not related to WASM build
 */

var lastError error

//export FreePointer
func FreePointer(pointer unsafe.Pointer) {
	C.free(pointer)
}

//export IsError
func IsError() bool {
	return lastError != nil
}

//export GetError
func GetError() *C.char {
	if lastError == nil {
		return C.CString("")
	}
	msg := lastError.Error()
	lastError = nil
	return C.CString(msg)
}

//export Random
func Random(size C.int) unsafe.Pointer {
	data, err := base.Random(int(size))
	lastError = err
	return C.CBytes(data)
}

//export MD5
func MD5(raw unsafe.Pointer, size C.int) unsafe.Pointer {
	var err error
	data := C.GoBytes(raw, size)
	data, err = base.MD5(data)
	lastError = err
	return C.CBytes(data)
}

//export Sha_1
func Sha_1(raw unsafe.Pointer, size C.int) unsafe.Pointer {
	var err error
	data := C.GoBytes(raw, size)
	data, err = base.Sha1(data)
	lastError = err
	return C.CBytes(data)
}

//export Sha_224
func Sha_224(raw unsafe.Pointer, size C.int) unsafe.Pointer {
	var err error
	data := C.GoBytes(raw, size)
	data, err = base.Sha224(data)
	lastError = err
	return C.CBytes(data)
}

//export Sha_256
func Sha_256(raw unsafe.Pointer, size C.int) unsafe.Pointer {
	var err error
	data := C.GoBytes(raw, size)
	data, err = base.Sha256(data)
	lastError = err
	return C.CBytes(data)
}

//export Sha_384
func Sha_384(raw unsafe.Pointer, size C.int) unsafe.Pointer {
	var err error
	data := C.GoBytes(raw, size)
	data, err = base.Sha384(data)
	lastError = err
	return C.CBytes(data)
}

//export Sha_512
func Sha_512(raw unsafe.Pointer, size C.int) unsafe.Pointer {
	var err error
	data := C.GoBytes(raw, size)
	data, err = base.Sha512(data)
	lastError = err
	return C.CBytes(data)
}

//export Hmac_1_Sign
func Hmac_1_Sign(data unsafe.Pointer, size C.int, key unsafe.Pointer) unsafe.Pointer {
	_data := C.GoBytes(data, size)
	_key := C.GoBytes(key, 16)
	raw := base.Hmac1Sign(_data, _key)
	return C.CBytes(raw)
}

//export Hmac_256_Sign
func Hmac_256_Sign(data unsafe.Pointer, size C.int, key unsafe.Pointer) unsafe.Pointer {
	_data := C.GoBytes(data, size)
	_key := C.GoBytes(key, 32)
	raw := base.Hmac256Sign(_data, _key)
	return C.CBytes(raw)
}

//export Hmac_384_Sign
func Hmac_384_Sign(data unsafe.Pointer, size C.int, key unsafe.Pointer) unsafe.Pointer {
	_data := C.GoBytes(data, size)
	_key := C.GoBytes(key, 48)
	raw := base.Hmac384Sign(_data, _key)
	return C.CBytes(raw)
}

//export Hmac_512_Sign
func Hmac_512_Sign(data unsafe.Pointer, size C.int, key unsafe.Pointer) unsafe.Pointer {
	_data := C.GoBytes(data, size)
	_key := C.GoBytes(key, 64)
	raw := base.Hmac512Sign(_data, _key)
	return C.CBytes(raw)
}

//export Hmac_1_Verify
func Hmac_1_Verify(data unsafe.Pointer, size C.int, mac, key unsafe.Pointer) bool {
	_data := C.GoBytes(data, size)
	_mac := C.GoBytes(mac, 20)
	_key := C.GoBytes(key, 16)
	return base.Hmac1Verify(_data, _mac, _key)
}

//export Hmac_256_Verify
func Hmac_256_Verify(data unsafe.Pointer, size C.int, mac, key unsafe.Pointer) bool {
	_data := C.GoBytes(data, size)
	_mac := C.GoBytes(mac, 32)
	_key := C.GoBytes(key, 32)
	return base.Hmac256Verify(_data, _mac, _key)
}

//export Hmac_384_Verify
func Hmac_384_Verify(data unsafe.Pointer, size C.int, mac, key unsafe.Pointer) bool {
	_data := C.GoBytes(data, size)
	_mac := C.GoBytes(mac, 48)
	_key := C.GoBytes(key, 48)
	return base.Hmac384Verify(_data, _mac, _key)
}

//export Hmac_512_Verify
func Hmac_512_Verify(data unsafe.Pointer, size C.int, mac, key unsafe.Pointer) bool {
	_data := C.GoBytes(data, size)
	_mac := C.GoBytes(mac, 64)
	_key := C.GoBytes(key, 64)
	return base.Hmac512Verify(_data, _mac, _key)
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

//export X25519_Remove_Key
func X25519_Remove_Key(id string, pub bool) bool {
	return x25519.RemoveKey(id, pub)
}

//export X25519_Import_Public_Key
func X25519_Import_Public_Key(raw []byte) string {
	data, err := x25519.ImportPublicKey(raw)
	lastError = err
	return data
}

//export X25519_Import_Private_Key
func X25519_Import_Private_Key(raw []byte) string {
	data, err := x25519.ImportPrivateKey(raw)
	lastError = err
	return data
}

//export X25519_Import_JWK
func X25519_Import_JWK(jsObj *map[string]string) string {

	keys := []string{"d", "x", "y"}
	jsRaw, err := decodeJWK(jsObj, keys)
	if err != nil {
		lastError = err
		return ""
	}

	data, err := x25519.ImportJWK(jsRaw)
	lastError = err
	return data
}

//export X25519_Has_Key
func X25519_Has_Key(id string, pub bool) bool {
	return x25519.HasKey(id, pub)
}

//export X25519_Generate_Key
func X25519_Generate_Key() string {
	data, err := x25519.GenerateKey()
	lastError = err
	return data
}

//export X25519_Export_Public_Key_Raw
func X25519_Export_Public_Key_Raw(id string) []byte {
	data, err := x25519.ExportPublicKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export X25519_Export_Public_Key_Pem
func X25519_Export_Public_Key_Pem(id string) string {
	data, err := x25519.ExportPublicKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export X25519_Export_Public_Key_JWK
func X25519_Export_Public_Key_JWK(id string) map[string]string {
	data, err := x25519.ExportPublicKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export X25519_Export_Private_Key_Raw
func X25519_Export_Private_Key_Raw(id string) []byte {
	data, err := x25519.ExportPrivateKey(id, lib.FormatRaw)
	lastError = err
	return data.([]byte)
}

//export X25519_Export_Private_Key_Pem
func X25519_Export_Private_Key_Pem(id string) string {
	data, err := x25519.ExportPrivateKey(id, lib.FormatPem)
	lastError = err
	return data.(string)
}

//export X25519_Export_Private_Key_JWK
func X25519_Export_Private_Key_JWK(id string) map[string]string {
	data, err := x25519.ExportPrivateKey(id, lib.FormatJWK)
	lastError = err
	return data.(map[string]string)
}

//export X25519_Derive_Key
func X25519_Derive_Key(priv, pub string, bitLen int) []byte {
	data, err := x25519.DeriveKey(priv, pub, bitLen)
	lastError = err
	return data
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
