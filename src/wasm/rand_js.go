//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptojs/src/base"
)

// InitRand register random generator engine to the globalThis.CryptoWasm
func InitRand(root js.Value) {
	root.Set("random", js.FuncOf(randomJS))
}

func randomJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	size := args[0].Int()

	res, err := base.Random(size)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(res)
}
