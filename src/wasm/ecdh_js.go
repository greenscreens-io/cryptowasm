//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

// https://pkg.go.dev/crypto/ecdh in 1.20v when released

import (
	"syscall/js"
	"wasm/cryptojs/src/ecdh"
	"wasm/cryptojs/src/lib"
)

// InitEcdh register ecdh engine to the globalThis.CryptoWasm
func InitEcdh(root js.Value) {
	ecdhObj := initChild("ecdh", root)
	ecdhObj.Set("GenerateKey", js.FuncOf(generateKeyEcdhJS))
	ecdhObj.Set("ImportJWK", js.FuncOf(importJWKECDHJS))
	ecdhObj.Set("ImportKey", js.FuncOf(importKeyEcdhJS))
	ecdhObj.Set("ExportKey", js.FuncOf(exportKeyEcdhJS))
	ecdhObj.Set("RemoveKey", js.FuncOf(removeKeyEcdhJS))
	ecdhObj.Set("HasKey", js.FuncOf(hasKeyEcdhJS))
	ecdhObj.Set("DeriveKey", js.FuncOf(deriveKeyEcdhJS))
}

func generateKeyEcdhJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	data, err := ecdh.GenerateKey(args[0].Int())
	if err != nil {
		return errorToJS(err)
	}

	return data
}

func importJWKECDHJS(this js.Value, args []js.Value) any {

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

	result, err := ecdh.ImportJWK(&raw, jsObj.Get("crv").String())
	if err != nil {
		return errorToJS(err)
	}
	return result
}

func importKeyEcdhJS(this js.Value, args []js.Value) any {

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
		data, err = ecdh.ImportPublicKey(data)
	} else {
		data, err = ecdh.ImportPrivateKey(data)
	}

	if err != nil {
		return errorToJS(err)
	}

	return data
}

func exportKeyEcdhJS(this js.Value, args []js.Value) any {

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
		data, err = ecdh.ExportPublicKey(id, lib.Format(fmt))
	} else {
		data, err = ecdh.ExportPrivateKey(id, lib.Format(fmt))
	}

	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyEcdhJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return ecdh.RemoveKey(id, isPublic)
}

func hasKeyEcdhJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return ecdh.HasKey(id, isPublic)
}

func deriveKeyEcdhJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeString, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	privateKey := args[0].String()
	publicKey := args[1].String()
	bitLength := args[2].Int()

	result, err := ecdh.DeriveKey(privateKey, publicKey, bitLength)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}
