//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptojs/src/base"
)

type hashfn func([]byte) ([]byte, error)

// InitHash register hash engine to the globalThis.CryptoWasm
func InitHash(root js.Value) {
	hashObj := initChild("hash", root)
	hashObj.Set("MD5", js.FuncOf(md5js))
	hashObj.Set("Sha1", js.FuncOf(sha1js))
	hashObj.Set("Sha224", js.FuncOf(sha224js))
	hashObj.Set("Sha256", js.FuncOf(sha256js))
	hashObj.Set("Sha384", js.FuncOf(sha384js))
	hashObj.Set("Sha512", js.FuncOf(sha512js))
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
