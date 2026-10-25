//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptowasm/src/base"
)

type hashfn func([]byte) ([]byte, error)
type shakefn func(resultLen int, data, customization, N []byte) ([]byte, error)

// InitHash register hash engine to the globalThis.CryptoWasm
func InitHash(root js.Value) {
	hashObj := initChild("hash", root)
	hashObj.Set("MD5", js.FuncOf(md5js))
	hashObj.Set("Sha1", js.FuncOf(sha1js))
	hashObj.Set("Sha224", js.FuncOf(sha224js))
	hashObj.Set("Sha256", js.FuncOf(sha256js))
	hashObj.Set("Sha384", js.FuncOf(sha384js))
	hashObj.Set("Sha512", js.FuncOf(sha512js))
	hashObj.Set("Sha3-256", js.FuncOf(sha3_256js))
	hashObj.Set("Sha3-384", js.FuncOf(sha3_384js))
	hashObj.Set("Sha3-512", js.FuncOf(sha3_512js))
	// Web Crypto API Version 2
	// https://wicg.github.io/webcrypto-modern-algos/#cshake
	hashObj.Set("CShake-128", js.FuncOf(cshake_128js))
	hashObj.Set("CShake-256", js.FuncOf(cshake_256js))
}

func md5js(this js.Value, args []js.Value) any {
	return hasher(args, base.MD5)
}

func sha1js(this js.Value, args []js.Value) any {
	return hasher(args, base.Sha1)
}

func sha224js(this js.Value, args []js.Value) any {
	return hasher(args, base.Sha224)
}

func sha256js(this js.Value, args []js.Value) any {
	return hasher(args, base.Sha256)
}

func sha384js(this js.Value, args []js.Value) any {
	return hasher(args, base.Sha384)
}

func sha512js(this js.Value, args []js.Value) any {
	return hasher(args, base.Sha512)
}

func sha3_256js(this js.Value, args []js.Value) any {
	return hasher(args, base.Sha3_256)
}

func sha3_384js(this js.Value, args []js.Value) any {
	return hasher(args, base.Sha3_384)
}

func sha3_512js(this js.Value, args []js.Value) any {
	return hasher(args, base.Sha3_512)
}

func hasher(args []js.Value, fn hashfn) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[0])
	if err != nil {
		return errorToJS(err)
	}

	result, err := fn(data)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func cshake_128js(this js.Value, args []js.Value) any {
	return shaker(args, base.CShake_128)
}

func cshake_256js(this js.Value, args []js.Value) any {
	return shaker(args, base.CShake_256)
}

func shaker(args []js.Value, fn shakefn) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber, TypeUint8Array, TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	resultLen := args[0].Int()

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	customization, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	result, err := fn(resultLen, data, customization, nil)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}
