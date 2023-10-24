//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptowasm/src/base"
)

// InitHKDF register HKDF engine to the globalThis.CryptoWasm
func InitHKDF(root js.Value) {
	root.Set("GenerateHKDF", js.FuncOf(deriveHKDFJS))
}

func deriveHKDFJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, TypeUint8Array, TypeUint8Array, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	secret, err := toNative(args[0])
	if err != nil {
		return errorToJS(err)
	}

	salt, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	info, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	size := args[3].Int()

	res, err := base.GenerateHKDF(secret, salt, info, size)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(res)
}
