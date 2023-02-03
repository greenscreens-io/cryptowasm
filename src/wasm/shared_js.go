//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"encoding/base64"
	"encoding/hex"
	"syscall/js"

	"github.com/google/uuid"
)

// InitUtil register utility functions to the globalThis.CryptoWasm
func InitUtil(root js.Value) {
	root.Set("fromHex", js.FuncOf(fromHexJS))
	root.Set("toHex", js.FuncOf(toHexJS))
	root.Set("fromB64", js.FuncOf(fromB64JS))
	root.Set("toB64", js.FuncOf(toB64JS))
	root.Set("randomUUID", js.FuncOf(randomUUIDJS))
}

func randomUUIDJS(this js.Value, args []js.Value) any {
	gc_wait = true
	return uuid.New().String()
}

func fromHexJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	r, err := hex.DecodeString(args[0].String())
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(r)
}

func toHexJS(this js.Value, args []js.Value) any {

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

	return hex.EncodeToString(data)
}

func fromB64JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	data := args[0].String()
	asURL := args[1].Bool()

	var raw []byte
	if asURL {
		raw, err = base64.RawURLEncoding.DecodeString(data)
	} else {
		raw, err = base64.StdEncoding.DecodeString(data)
	}

	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(raw)
}

func toB64JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, js.TypeBoolean}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	asURL := args[1].Bool()
	data, err := toNative(args[0])
	if err != nil {
		return errorToJS(err)
	}

	if asURL {
		return base64.RawURLEncoding.EncodeToString(data)
	} else {
		return base64.StdEncoding.EncodeToString(data)
	}

}
