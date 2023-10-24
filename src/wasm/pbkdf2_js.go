//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptowasm/src/base"
)

// InitPBKDF2 register PBKDF2 engine to the globalThis.CryptoWasm
func InitPBKDF2(root js.Value) {
	root.Set("GeneratePBKDF2", js.FuncOf(pbkdf2JS))
}

func pbkdf2JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, TypeUint8Array, js.TypeNumber, js.TypeNumber, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	password, err := toNative(args[0])
	if err != nil {
		return errorToJS(err)
	}

	salt, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	iter := args[2].Int()
	keyLen := args[3].Int()
	hashLen := args[4].Int()

	res, err := base.GeneratePBKDF2(password, salt, iter, keyLen, hashLen)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(res)
}
