//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

// https://pkg.go.dev/crypto/ecdh in 1.20v when released
// https://wicg.github.io/webcrypto-secure-curves/#x25519-description

import (
	"syscall/js"
	"wasm/cryptojs/src/lib"
	"wasm/cryptojs/src/x25519"
)

// InitEcdh register x25519 engine to the globalThis.CryptoWasm
func InitX25519(root js.Value) {
	x25519 := initChild("x25519", root)
	x25519.Set("GenerateKey", js.FuncOf(generateKeyX25519JS))
	x25519.Set("ImportJWK", js.FuncOf(importJWKX25519JS))
	x25519.Set("ImportKey", js.FuncOf(importKeyX25519JS))
	x25519.Set("ExportKey", js.FuncOf(exportKeyX25519JS))
	x25519.Set("RemoveKey", js.FuncOf(removeKeyX25519JS))
	x25519.Set("HasKey", js.FuncOf(hasKeyX25519JS))
	x25519.Set("DeriveKey", js.FuncOf(deriveKeyX25519JS))
}

func generateKeyX25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	data, err := x25519.GenerateKey()
	if err != nil {
		return errorToJS(err)
	}

	return data
}

func importJWKX25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeObject}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	raw := map[string][]byte{}
	jsObj := args[0]

	l := []string{"d", "x", "y"}
	for _, v := range l {
		err = decodeB64(v, &jsObj, &raw)
		if err != nil {
			return errorToJS(err)
		}
	}

	result, err := x25519.ImportJWK(&raw)
	if err != nil {
		return errorToJS(err)
	}
	return result
}

func importKeyX25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	val := args[0]
	isPub := getAsBool(&args, 1, false)

	var data any

	isString := isString(val)
	if isString {
		data = val.String()
	} else {
		data, err = toNative(val)
	}

	if err != nil {
		return errorToJS(err)
	}

	if isPub {
		data, err = x25519.ImportPublicKey(data)
	} else {
		data, err = x25519.ImportPrivateKey(data)
	}

	if err != nil {
		return errorToJS(err)
	}

	return data
}

func exportKeyX25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, js.TypeBoolean, js.TypeNumber}
	_, err := validateJSArgs(args, types, []int{1, 2, 3})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPub := getAsBool(&args, 1, false)
	fmt := getAsInt(&args, 2, int(lib.FormatRaw))

	var data any

	if isPub {
		data, err = x25519.ExportPublicKey(id, lib.Format(fmt))
	} else {
		data, err = x25519.ExportPrivateKey(id, lib.Format(fmt))
	}

	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyX25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return x25519.RemoveKey(id, isPublic)
}

func hasKeyX25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return x25519.HasKey(id, isPublic)
}

func deriveKeyX25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeString, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	privateKey := args[0].String()
	publicKey := args[1].String()
	bitLength := args[2].Int()

	result, err := x25519.DeriveKey(privateKey, publicKey, bitLength)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}
