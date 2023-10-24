//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptowasm/src/ecdsa"
	"wasm/cryptowasm/src/lib"
)

// InitEcdsa register ecdsa engine to the globalThis.CryptoWasm
func InitEcdsa(root js.Value) {
	ecdsaObj := initChild("ecdsa", root)
	ecdsaObj.Set("GenerateKey", js.FuncOf(generateKeyECDSAJS))
	ecdsaObj.Set("ImportJWK", js.FuncOf(importJWKECDSAJS))
	ecdsaObj.Set("ImportKey", js.FuncOf(importKeyECDSAJS))
	ecdsaObj.Set("ExportKey", js.FuncOf(exportKeyECDSAJS))
	ecdsaObj.Set("RemoveKey", js.FuncOf(removeKeyECDSAJS))
	ecdsaObj.Set("HasKey", js.FuncOf(hasKeyECDSAJS))
	ecdsaObj.Set("Sign", js.FuncOf(signECDSAJS))
	ecdsaObj.Set("Verify", js.FuncOf(verifyECDSAJS))
}

func generateKeyECDSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	keySize := args[0].Int()

	data, err := ecdsa.GenerateKey(keySize)
	if err != nil {
		return errorToJS(err)
	}

	return data
}

func signECDSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, js.TypeNumber, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{3, 4})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	size := args[2].Int()

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	asn := getAsBool(&args, 3, false)

	result, err := ecdsa.Sign(id, data, size, asn)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func verifyECDSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, TypeUint8Array, js.TypeNumber, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{4, 5})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	size := args[3].Int()

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	sign, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	asn := getAsBool(&args, 4, false)

	return ecdsa.Verify(id, data, sign, size, asn)

}

func importJWKECDSAJS(this js.Value, args []js.Value) any {

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

	result, err := ecdsa.ImportJWK(&raw, jsObj.Get("crv").String())
	if err != nil {
		return errorToJS(err)
	}

	return result
}

func importKeyECDSAJS(this js.Value, args []js.Value) any {

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
		data, err = ecdsa.ImportPublicKey(data)
	} else {
		data, err = ecdsa.ImportPrivateKey(data)
	}

	if err != nil {
		return errorToJS(err)
	}

	return data

}

func exportKeyECDSAJS(this js.Value, args []js.Value) any {

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
		data, err = ecdsa.ExportPublicKey(id, lib.Format(fmt))
	} else {
		data, err = ecdsa.ExportPrivateKey(id, lib.Format(fmt))
	}

	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyECDSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return ecdsa.RemoveKey(id, isPublic)
}

func hasKeyECDSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return ecdsa.HasKey(id, isPublic)
}
