//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

//README https://wicg.github.io/webcrypto-modern-algos/#ml-dsa

import (
	"syscall/js"
	"wasm/cryptowasm/src/lib"
	"wasm/cryptowasm/src/mldsa"
)

// InitMlDsa register ecdsa engine to the globalThis.CryptoWasm
func InitMlDsa(root js.Value) {
	ecdsaObj := initChild("mlkem", root)
	ecdsaObj.Set("GenerateKey", js.FuncOf(generateKeyMLDSA))
	ecdsaObj.Set("Sign", js.FuncOf(signMLDSA))
	ecdsaObj.Set("Verify", js.FuncOf(verifyMLDSA))
	ecdsaObj.Set("ImportJWK", js.FuncOf(importJWKMLDSA))
	ecdsaObj.Set("ImportKey", js.FuncOf(importKeyMLDSA))
	ecdsaObj.Set("ExportKey", js.FuncOf(exportKeyMLDSA))
	ecdsaObj.Set("RemoveKey", js.FuncOf(removeKeyMLDSA))
	ecdsaObj.Set("HasKey", js.FuncOf(hasKeyMLDSA))
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

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	return nil
}

func verifyMLDSA(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	return nil
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

	l := []string{"pub", "priv"}
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
		data, err = mldsa.ImportPublicKey(data)
	} else {
		data, err = mldsa.ImportPrivateKey(data)
	}

	if err != nil {
		return errorToJS(err)
	}

	return data

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
