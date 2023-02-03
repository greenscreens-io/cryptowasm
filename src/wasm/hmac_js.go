//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptojs/src/base"
)

type hmacSignFn func([]byte, []byte) []byte
type hmacVerifyFn func([]byte, []byte, []byte) bool

// InitHmac register hmac engine to the globalThis.CryptoWasm
func InitHmac(root js.Value) {
	hmacObj := initChild("hmac", root)
	hmacObj.Set("Hmac1Sign", js.FuncOf(hmac1SignJS))
	hmacObj.Set("Hmac1Verify", js.FuncOf(hmac1VerifyJS))
	hmacObj.Set("Hmac256Sign", js.FuncOf(hmac256SignJS))
	hmacObj.Set("Hmac384Sign", js.FuncOf(hmac384SignJS))
	hmacObj.Set("Hmac512Sign", js.FuncOf(hmac512SignJS))
	hmacObj.Set("Hmac1Verify", js.FuncOf(hmac1VerifyJS))
	hmacObj.Set("Hmac256Verify", js.FuncOf(hmac256VerifyJS))
	hmacObj.Set("Hmac384Verify", js.FuncOf(hmac384VerifyJS))
	hmacObj.Set("Hmac512Verify", js.FuncOf(hmac512VerifyJS))
}

func hmac1SignJS(this js.Value, args []js.Value) any {
	return doHmacSign(args, base.Hmac1Sign)
}

func hmac256SignJS(this js.Value, args []js.Value) any {
	return doHmacSign(args, base.Hmac256Sign)
}

func hmac384SignJS(this js.Value, args []js.Value) any {
	return doHmacSign(args, base.Hmac384Sign)
}

func hmac512SignJS(this js.Value, args []js.Value) any {
	return doHmacSign(args, base.Hmac512Sign)
}

func hmac1VerifyJS(this js.Value, args []js.Value) any {
	return doHmacVerify(args, base.Hmac1Verify)
}

func hmac256VerifyJS(this js.Value, args []js.Value) any {
	return doHmacVerify(args, base.Hmac256Verify)
}

func hmac384VerifyJS(this js.Value, args []js.Value) any {
	return doHmacVerify(args, base.Hmac384Verify)
}

func hmac512VerifyJS(this js.Value, args []js.Value) any {
	return doHmacVerify(args, base.Hmac512Verify)
}

func doHmacSign(args []js.Value, fn hmacSignFn) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[0])
	if err != nil {
		return errorToJS(err)
	}

	key, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	result := fn(data, key)

	return bytesToJS(result)
}

func doHmacVerify(args []js.Value, fn hmacVerifyFn) any {

	types := []js.Type{TypeUint8Array, TypeUint8Array, TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[0])
	if err != nil {
		return errorToJS(err)
	}

	mac, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	key, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	return fn(data, mac, key)
}
