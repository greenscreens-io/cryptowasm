//go:build js && wasm

/*
 * Copyright (C) 2015, 2026 Green Screens Ltd.
 */
package wasm

//README https://wicg.github.io/webcrypto-modern-algos/#ml-dsa

import (
	"syscall/js"
	"wasm/cryptowasm/src/lib"
	"wasm/cryptowasm/src/mldsa"
)

// InitMlDsa registers the ML-DSA engine on globalThis.CryptoWasm.
func InitMlDsa(root js.Value) {
	mldsaObj := initChild("mldsa", root)
	mldsaObj.Set("GenerateKey", js.FuncOf(generateKeyMLDSA))
	mldsaObj.Set("Sign", js.FuncOf(signMLDSA))
	mldsaObj.Set("Verify", js.FuncOf(verifyMLDSA))
	mldsaObj.Set("ImportJWK", js.FuncOf(importJWKMLDSA))
	mldsaObj.Set("ImportKey", js.FuncOf(importKeyMLDSA))
	mldsaObj.Set("ExportKey", js.FuncOf(exportKeyMLDSA))
	mldsaObj.Set("RemoveKey", js.FuncOf(removeKeyMLDSA))
	mldsaObj.Set("HasKey", js.FuncOf(hasKeyMLDSA))
}

func generateKeyMLDSA(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	keySize := args[0].Int()

	data, err := mldsa.GenerateKey(keySize)
	if err != nil {
		return errorToJS(err)
	}

	return data
}

func signMLDSA(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, js.TypeString}
	_, err := validateJSArgs(args, types, []int{2, 3})
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	result, err := mldsa.Sign(args[0].String(), data, optionalString(args, 2))
	if err != nil {
		return errorToJS(err)
	}
	return bytesToJS(result)
}

func verifyMLDSA(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, TypeUint8Array, js.TypeString}
	_, err := validateJSArgs(args, types, []int{3, 4})
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}
	signature, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}
	valid, err := mldsa.Verify(args[0].String(), data, signature, optionalString(args, 3))
	if err != nil {
		return errorToJS(err)
	}
	return valid
}

func importJWKMLDSA(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeObject}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	raw := map[string][]byte{}
	jsObj := args[0]

	l := []string{"priv", "pub"}
	for _, v := range l {
		err = decodeB64(v, &jsObj, &raw)
		if err != nil {
			return errorToJS(err)
		}
	}

	result, err := mldsa.ImportJWK(&raw, jsObj.Get("crv").String())
	if err != nil {
		return errorToJS(err)
	}

	return result
}

func importKeyMLDSA(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, js.TypeBoolean, js.TypeString}
	_, err := validateJSArgs(args, types, []int{1, 2, 3})
	if err != nil {
		return errorToJS(err)
	}

	val := args[0]
	isPub := getAsBool(&args, 1, false)
	algorithm := optionalString(args, 2)

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
		data, err = mldsa.ImportPublicKey(data)
	} else {
		data, err = mldsa.ImportPrivateKey(data, algorithm)
	}

	if err != nil {
		return errorToJS(err)
	}

	return data

}

func optionalString(args []js.Value, index int) string {
	if len(args) <= index {
		return ""
	}
	return args[index].String()
}

func exportKeyMLDSA(this js.Value, args []js.Value) any {

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
		data, err = mldsa.ExportPublicKey(id, lib.Format(fmt))
	} else {
		data, err = mldsa.ExportPrivateKey(id, lib.Format(fmt))
	}

	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyMLDSA(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return mldsa.RemoveKey(id, isPublic)
}

func hasKeyMLDSA(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return mldsa.HasKey(id, isPublic)
}
