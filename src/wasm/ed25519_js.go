//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptojs/src/ed25519"
	"wasm/cryptojs/src/lib"
)

// InitED25519 register ed25519 engine to the globalThis.CryptoWasm
func InitED25519(root js.Value) {
	ed25519Obj := initChild("ed25519", root)
	ed25519Obj.Set("GenerateKey", js.FuncOf(generateKeyED25519JS))
	ed25519Obj.Set("ImportJWK", js.FuncOf(importJWKED25519JS))
	ed25519Obj.Set("ImportKey", js.FuncOf(importKeyED25519JS))
	ed25519Obj.Set("ExportKey", js.FuncOf(exportKeyED25519JS))
	ed25519Obj.Set("RemoveKey", js.FuncOf(removeKeyED25519JS))
	ed25519Obj.Set("HasKey", js.FuncOf(hasKeyED25519JS))
	ed25519Obj.Set("Sign", js.FuncOf(signED25519JS))
	ed25519Obj.Set("Verify", js.FuncOf(verifyED25519JS))
}

func generateKeyED25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	priv, err := ed25519.GenerateKey()
	if err != nil {
		return errorToJS(err)
	}

	return priv
}

func signED25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{2, 3})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	asn := getAsBool(&args, 2, false)

	result, err := ed25519.Sign(id, data, asn)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func verifyED25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, TypeUint8Array, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{3, 4})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	sign, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	asn := getAsBool(&args, 3, false)

	sts, err := ed25519.Verify(id, data, sign, asn)
	if err != nil {
		return errorToJS(err)
	}

	return sts

}

func importJWKED25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeObject}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	raw := map[string][]byte{}
	jsObj := args[0]

	l := []string{"d", "x"}
	for _, v := range l {
		err = decodeB64(v, &jsObj, &raw)
		if err != nil {
			return errorToJS(err)
		}
	}

	result, err := ed25519.ImportJWK(&raw)
	if err != nil {
		return errorToJS(err)
	}

	return result
}

func importKeyED25519JS(this js.Value, args []js.Value) any {

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
		data, err = ed25519.ImportPublicKey(data)
	} else {
		data, err = ed25519.ImportPrivateKey(data)
	}

	if err != nil {
		return errorToJS(err)
	}

	return data

}

func exportKeyED25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean, js.TypeNumber}
	_, err := validateJSArgs(args, types, []int{1, 2, 3})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPub := getAsBool(&args, 1, false)
	fmt := getAsInt(&args, 2, int(lib.FormatRaw))

	var data any

	if isPub {
		data, err = ed25519.ExportPublicKey(id, lib.Format(fmt))
	} else {
		data, err = ed25519.ExportPrivateKey(id, lib.Format(fmt))
	}

	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyED25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return ed25519.RemoveKey(id, isPublic)
}

func hasKeyED25519JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return ed25519.HasKey(id, isPublic)
}
