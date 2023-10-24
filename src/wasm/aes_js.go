//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptowasm/src/base"
)

type synccrypt3fn func([]byte, []byte, []byte) ([]byte, error)

// InitAES register aes engine to the globalThis.CryptoWasm
func InitAES(root js.Value) {
	aesObj := initChild("aes", root)
	aesObj.Set("CBCEncrypt", js.FuncOf(CBCEncrypterJS))
	aesObj.Set("CBCDecrypt", js.FuncOf(CBCDecrypterJS))
	aesObj.Set("CTREncrypt", js.FuncOf(CTREncrypterJS))
	aesObj.Set("CTRDecrypt", js.FuncOf(CTRDecrypterJS))
	aesObj.Set("GCMEncrypt", js.FuncOf(GCMEncrypterJS))
	aesObj.Set("GCMDecrypt", js.FuncOf(GCMDecrypterJS))
}

func CBCEncrypterJS(this js.Value, args []js.Value) any {
	return synccrypt3(args, base.CBCEncrypter)
}

func CBCDecrypterJS(this js.Value, args []js.Value) any {
	return synccrypt3(args, base.CBCDecrypter)
}

func CTREncrypterJS(this js.Value, args []js.Value) any {
	return synccrypt3(args, base.CTREncrypter)
}

func CTRDecrypterJS(this js.Value, args []js.Value) any {
	return synccrypt3(args, base.CTRDecrypter)
}

func GCMEncrypterJS(this js.Value, args []js.Value) any {
	return synccrypt3(args, base.GCMEencrypter)
}

func GCMDecrypterJS(this js.Value, args []js.Value) any {
	return synccrypt3(args, base.GCMDecrypter)
}

func synccrypt3(args []js.Value, fn synccrypt3fn) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, TypeUint8Array, TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	key, err := toNative(args[0])
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	iv, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	result, err := fn(key, data, iv)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}
