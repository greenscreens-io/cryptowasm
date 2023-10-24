//go:build windows

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package main

// #include <stdlib.h>
import "C"
import (
	"encoding/base64"
	"encoding/json"
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
func HKDF_Generate_Key(secret, salt, info unsafe.Pointer, l1, l2, l3, size C.int) unsafe.Pointer {
	_secret := C.GoBytes(secret, l1)
	_salt := C.GoBytes(salt, l2)
	var _info []byte
	if info != nil {
		_info = C.GoBytes(info, l3)
	}
	data, err := base.GenerateHKDF(_secret, _salt, _info, int(size))
	lastError = err
	return C.CBytes(data)
}

//export PBKDF2_Generate_Key
func PBKDF2_Generate_Key(secret, salt unsafe.Pointer, l1, l2, iter, keyLen, hashLen C.int) unsafe.Pointer {
	_secret := C.GoBytes(secret, l1)
	_salt := C.GoBytes(salt, l2)
	data, err := base.GeneratePBKDF2(_secret, _salt, int(iter), int(keyLen), int(hashLen))
	lastError = err
	return C.CBytes(data)
}

//export RSA_Decrypt
func RSA_Decrypt(id *C.char, size C.int, data unsafe.Pointer, len C.int) unsafe.Pointer {
	_id := C.GoString(id)
	_data := C.GoBytes(data, len)
	res, err := rsa.Decrypt(_id, int(size), _data)
	lastError = err
	return C.CBytes(res)
}

//export RSA_Encrypt
func RSA_Encrypt(id *C.char, size C.int, data unsafe.Pointer, len C.int) unsafe.Pointer {
	_id := C.GoString(id)
	_data := C.GoBytes(data, len)
	res, err := rsa.Encrypt(_id, int(size), _data)
	lastError = err
	return C.CBytes(res)
}

//export RSA_Export_Private_Key_Raw
func RSA_Export_Private_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := rsa.ExportPrivateKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export RSA_Export_Private_Key_Pem
func RSA_Export_Private_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := rsa.ExportPrivateKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export RSA_Export_Private_Key_Jwk
func RSA_Export_Private_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := rsa.ExportPrivateKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	r, err := json.Marshal(data.(map[string]any))
	lastError = err
	return C.CString(string(r))
}

//export RSA_Export_Public_Key_Raw
func RSA_Export_Public_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := rsa.ExportPublicKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export RSA_Export_Public_Key_Pem
func RSA_Export_Public_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := rsa.ExportPublicKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export RSA_Export_Public_Key_Jwk
func RSA_Export_Public_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := rsa.ExportPublicKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	r, err := json.Marshal(data.(map[string]any))
	lastError = err
	return C.CString(string(r))
}

//export RSA_Generate_Key
func RSA_Generate_Key(size, publicExponent C.int) *C.char {
	data, err := rsa.GenerateKey(int(size), int(publicExponent))
	lastError = err
	return C.CString(data)
}

//export RSA_Has_Key
func RSA_Has_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return rsa.HasKey(_id, pub)
}

//export RSA_Import_Jwk
func RSA_Import_Jwk(jsStr *C.char) *C.char {

	keys := []string{"e", "n", "d", "p", "q", "qi", "dp", "dq"}
	jsRaw, err := decodeJWK(jsStr, keys)
	if err != nil {
		lastError = err
		return C.CString("")
	}

	data, err := rsa.ImportJWK(jsRaw)
	lastError = err
	return C.CString(data)
}

//export RSA_Import_Private_Key
func RSA_Import_Private_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := rsa.ImportPrivateKey(_raw)
	lastError = err
	return C.CString(data)
}

//export RSA_Import_Public_Key
func RSA_Import_Public_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := rsa.ImportPublicKey(_raw)
	lastError = err
	return C.CString(data)
}

//export RSA_Remove_Key
func RSA_Remove_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return rsa.RemoveKey(_id, pub)
}

//export RSA_Sign_PKCS_1v15
func RSA_Sign_PKCS_1v15(id *C.char, raw unsafe.Pointer, len, size C.int) unsafe.Pointer {
	_id := C.GoString(id)
	_raw := C.GoBytes(raw, len)
	data, err := rsa.SignPKCS1v15(_id, _raw, int(size))
	lastError = err
	return C.CBytes(data)
}

//export RSA_Sign_PSS
func RSA_Sign_PSS(id *C.char, raw unsafe.Pointer, len, hashLength, saltLength C.int) unsafe.Pointer {
	_id := C.GoString(id)
	_raw := C.GoBytes(raw, len)
	data, err := rsa.SignPSS(_id, _raw, int(hashLength), int(saltLength))
	lastError = err
	return C.CBytes(data)
}

//export RSA_Verify_PKCS_1v15
func RSA_Verify_PKCS_1v15(id *C.char, data, signature unsafe.Pointer, l1, l2, size C.int) bool {
	_id := C.GoString(id)
	_data := C.GoBytes(data, l1)
	_signature := C.GoBytes(signature, l2)
	err := rsa.VerifyPKCS1v15(_id, _data, _signature, int(size))
	lastError = err
	return err != nil
}

//export RSA_Verify_PSS
func RSA_Verify_PSS(id *C.char, data, signature unsafe.Pointer, l1, l2, hashLength, saltLength C.int) bool {
	_id := C.GoString(id)
	_data := C.GoBytes(data, l1)
	_signature := C.GoBytes(signature, l2)
	err := rsa.VerifyPSS(_id, _data, _signature, int(hashLength), int(saltLength))
	lastError = err
	return err != nil
}

//export ECDH_Remove_Key
func ECDH_Remove_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return ecdh.RemoveKey(_id, pub)
}

//export ECDH_Import_Public_Key
func ECDH_Import_Public_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := ecdh.ImportPublicKey(_raw)
	lastError = err
	return C.CString(data)
}

//export ECDH_Import_Private_Key
func ECDH_Import_Private_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := ecdh.ImportPrivateKey(_raw)
	lastError = err
	return C.CString(data)
}

//export ECDH_Import_Jwk
func ECDH_Import_Jwk(jsStr, curve *C.char) *C.char {

	keys := []string{"d", "x", "y"}
	jsRaw, err := decodeJWK(jsStr, keys)
	if err != nil {
		lastError = err
		return C.CString("")
	}

	_curve := C.GoString(curve)
	data, err := ecdh.ImportJWK(jsRaw, _curve)
	lastError = err
	return C.CString(data)
}

//export ECDH_Has_Key
func ECDH_Has_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return ecdh.HasKey(_id, pub)
}

//export ECDH_Generate_Key
func ECDH_Generate_Key(size C.int) *C.char {
	data, err := ecdh.GenerateKey(int(size))
	lastError = err
	return C.CString(data)
}

//export ECDH_Export_Public_Key_Raw
func ECDH_Export_Public_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := ecdh.ExportPublicKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export ECDH_Export_Public_Key_Pem
func ECDH_Export_Public_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ecdh.ExportPublicKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export ECDH_Export_Public_Key_Jwk
func ECDH_Export_Public_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ecdh.ExportPublicKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	jstr, err := json.Marshal(data.(map[string]string))
	lastError = err
	return C.CString(string(jstr))
}

//export ECDH_Export_Private_Key_Raw
func ECDH_Export_Private_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := ecdh.ExportPrivateKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export ECDH_Export_Private_Key_Pem
func ECDH_Export_Private_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ecdh.ExportPrivateKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export ECDH_Export_Private_Key_Jwk
func ECDH_Export_Private_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ecdh.ExportPrivateKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	jstr, err := json.Marshal(data.(map[string]string))
	lastError = err
	return C.CString(string(jstr))
}

//export ECDH_Derive_Key
func ECDH_Derive_Key(priv, pub *C.char, bitLen C.int) unsafe.Pointer {
	_priv := C.GoString(priv)
	_pub := C.GoString(pub)
	data, err := ecdh.DeriveKey(_priv, _pub, int(bitLen))
	lastError = err
	return C.CBytes(data)
}

//export ECDSA_Verify
func ECDSA_Verify(id *C.char, data, signature unsafe.Pointer, l1, l2, size C.int, asn bool) bool {
	_id := C.GoString(id)
	_data := C.GoBytes(data, l1)
	_signature := C.GoBytes(signature, l2)
	return ecdsa.Verify(_id, _data, _signature, int(size), asn)
}

//export ECDSA_Sign
func ECDSA_Sign(id *C.char, raw unsafe.Pointer, len, size C.int, asn bool) unsafe.Pointer {
	_id := C.GoString(id)
	_raw := C.GoBytes(raw, len)
	data, err := ecdsa.Sign(_id, _raw, int(size), asn)
	lastError = err
	return C.CBytes(data)
}

//export ECDSA_Remove_Key
func ECDSA_Remove_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return ecdsa.RemoveKey(_id, pub)
}

//export ECDSA_Import_Public_Key
func ECDSA_Import_Public_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := ecdsa.ImportPublicKey(_raw)
	lastError = err
	return C.CString(data)
}

//export ECDSA_Import_Private_Key
func ECDSA_Import_Private_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := ecdsa.ImportPrivateKey(_raw)
	lastError = err
	return C.CString(data)
}

//export ECDSA_Import_Jwk
func ECDSA_Import_Jwk(jsStr, curve *C.char) *C.char {

	_curve := C.GoString(curve)

	keys := []string{"d", "x", "y"}
	jsRaw, err := decodeJWK(jsStr, keys)
	if err != nil {
		lastError = err
		return C.CString("")
	}

	data, err := ecdsa.ImportJWK(jsRaw, _curve)
	lastError = err
	return C.CString(data)
}

//export ECDSA_Has_Key
func ECDSA_Has_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return ecdsa.HasKey(_id, pub)
}

//export ECDSA_Generate_Key
func ECDSA_Generate_Key(size C.int) *C.char {
	data, err := ecdsa.GenerateKey(int(size))
	lastError = err
	return C.CString(data)
}

//export ECDSA_Export_Public_Key_Raw
func ECDSA_Export_Public_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := ecdsa.ExportPublicKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export ECDSA_Export_Public_Key_Pem
func ECDSA_Export_Public_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ecdsa.ExportPublicKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export ECDSA_Export_Public_Key_Jwk
func ECDSA_Export_Public_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ecdsa.ExportPublicKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	r, err := json.Marshal(data.(map[string]any))
	lastError = err
	return C.CString(string(r))
}

//export ECDSA_Export_Private_Key_Raw
func ECDSA_Export_Private_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := ecdsa.ExportPrivateKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export ECDSA_Export_Private_Key_Pem
func ECDSA_Export_Private_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ecdsa.ExportPrivateKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export ECDSA_Export_Private_Key_Jwk
func ECDSA_Export_Private_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ecdsa.ExportPrivateKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	r, err := json.Marshal(data.(map[string]any))
	lastError = err
	return C.CString(string(r))
}

//export ED25519_Verify
func ED25519_Verify(pub *C.char, message, signature unsafe.Pointer, l1, l2 C.int, asn bool) bool {
	_pub := C.GoString(pub)
	_message := C.GoBytes(message, l1)
	_signature := C.GoBytes(signature, l2)
	data, err := ed25519.Verify(_pub, _message, _signature, asn)
	lastError = err
	return data
}

//export ED25519_Sign
func ED25519_Sign(priv *C.char, message unsafe.Pointer, len C.int, asn bool) unsafe.Pointer {
	_priv := C.GoString(priv)
	_message := C.GoBytes(message, len)
	data, err := ed25519.Sign(_priv, _message, asn)
	lastError = err
	return C.CBytes(data)
}

//export ED25519_Remove_Key
func ED25519_Remove_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return ed25519.RemoveKey(_id, pub)
}

//export ED25519_ImportPublic_Key
func ED25519_ImportPublic_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := ed25519.ImportPublicKey(_raw)
	lastError = err
	return C.CString(data)
}

//export ED25519_ImportPrivate_Key
func ED25519_ImportPrivate_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := ed25519.ImportPrivateKey(_raw)
	lastError = err
	return C.CString(data)
}

//export ED25519_Import_Jwk
func ED25519_Import_Jwk(jsStr *C.char) *C.char {

	keys := []string{"d", "x"}
	jsRaw, err := decodeJWK(jsStr, keys)
	if err != nil {
		lastError = err
		return C.CString("")
	}

	data, err := ed25519.ImportJWK(jsRaw)
	lastError = err
	return C.CString(data)
}

//export ED25519_Has_Key
func ED25519_Has_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return ed25519.HasKey(_id, pub)
}

//export ED25519_Generate_Key
func ED25519_Generate_Key() *C.char {
	data, err := ed25519.GenerateKey()
	lastError = err
	return C.CString(data)
}

//export ED25519_Export_Public_Key_Raw
func ED25519_Export_Public_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := ed25519.ExportPublicKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export ED25519_Export_Public_Key_Pem
func ED25519_Export_Public_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ed25519.ExportPublicKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export ED25519_Export_Public_Key_Jwk
func ED25519_Export_Public_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ed25519.ExportPublicKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	r, err := json.Marshal(data.(map[string]any))
	lastError = err
	return C.CString(string(r))
}

//export ED25519_Export_Private_Key_Raw
func ED25519_Export_Private_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := ed25519.ExportPrivateKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export ED25519_Export_Private_Key_Pem
func ED25519_Export_Private_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ed25519.ExportPrivateKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export ED25519_Export_Private_Key_Jwk
func ED25519_Export_Private_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := ed25519.ExportPrivateKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	r, err := json.Marshal(data.(map[string]any))
	lastError = err
	return C.CString(string(r))
}

//export X25519_Remove_Key
func X25519_Remove_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return x25519.RemoveKey(_id, pub)
}

//export X25519_Import_Public_Key
func X25519_Import_Public_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := x25519.ImportPublicKey(_raw)
	lastError = err
	return C.CString(data)
}

//export X25519_Import_Private_Key
func X25519_Import_Private_Key(raw unsafe.Pointer, len C.int) *C.char {
	_raw := C.GoBytes(raw, len)
	data, err := x25519.ImportPrivateKey(_raw)
	lastError = err
	return C.CString(data)
}

//export X25519_Import_Jwk
func X25519_Import_Jwk(jsStr *C.char) *C.char {

	keys := []string{"d", "x", "y"}
	jsRaw, err := decodeJWK(jsStr, keys)
	if err != nil {
		lastError = err
		return C.CString("")
	}

	data, err := x25519.ImportJWK(jsRaw)
	lastError = err
	return C.CString(data)
}

//export X25519_Has_Key
func X25519_Has_Key(id *C.char, pub bool) bool {
	_id := C.GoString(id)
	return x25519.HasKey(_id, pub)
}

//export X25519_Generate_Key
func X25519_Generate_Key() *C.char {
	data, err := x25519.GenerateKey()
	lastError = err
	return C.CString(data)
}

//export X25519_Export_Public_Key_Raw
func X25519_Export_Public_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := x25519.ExportPublicKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export X25519_Export_Public_Key_Pem
func X25519_Export_Public_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := x25519.ExportPublicKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export X25519_Export_Public_Key_Jwk
func X25519_Export_Public_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := x25519.ExportPublicKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	r, err := json.Marshal(data.(map[string]any))
	lastError = err
	return C.CString(string(r))
}

//export X25519_Export_Private_Key_Raw
func X25519_Export_Private_Key_Raw(id *C.char) unsafe.Pointer {
	_id := C.GoString(id)
	data, err := x25519.ExportPrivateKey(_id, lib.FormatRaw)
	lastError = err
	return C.CBytes(data.([]byte))
}

//export X25519_Export_Private_Key_Pem
func X25519_Export_Private_Key_Pem(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := x25519.ExportPrivateKey(_id, lib.FormatPem)
	lastError = err
	return C.CString(data.(string))
}

//export X25519_Export_Private_Key_Jwk
func X25519_Export_Private_Key_Jwk(id *C.char) *C.char {
	_id := C.GoString(id)
	data, err := x25519.ExportPrivateKey(_id, lib.FormatJWK)
	lastError = err
	if err != nil {
		return C.CString("")
	}
	r, err := json.Marshal(data.(map[string]any))
	lastError = err
	return C.CString(string(r))
}

//export X25519_Derive_Key
func X25519_Derive_Key(priv, pub *C.char, bitLen C.int) unsafe.Pointer {
	_priv := C.GoString(priv)
	_pub := C.GoString(pub)
	data, err := x25519.DeriveKey(_priv, _pub, int(bitLen))
	lastError = err
	return C.CBytes(data)
}

func decodeJWK(jsStr *C.char, keys []string) (*map[string][]byte, error) {

	str := C.GoString(jsStr)
	jsObj := make(map[string]string)
	json.Unmarshal([]byte(str), &jsObj)

	jsRaw := map[string][]byte{}

	for _, v := range keys {
		err := decodeB64(v, &jsObj, &jsRaw)
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
