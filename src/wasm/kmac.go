//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

// README https://wicg.github.io/webcrypto-modern-algos/#kmac

import (
	"syscall/js"
	"wasm/cryptowasm/src/kmac"
	"wasm/cryptowasm/src/lib"
)

// InitKmac register KMAC engine to the globalThis.CryptoWasm
func InitKmac(root js.Value) {
	ecdsaObj := initChild("mlkem", root)
	ecdsaObj.Set("GenerateKey", js.FuncOf(generateKeyKMAC))
	ecdsaObj.Set("Sign", js.FuncOf(generateKeyKMAC))
	ecdsaObj.Set("Verify", js.FuncOf(generateKeyKMAC))
	ecdsaObj.Set("ImportJWK", js.FuncOf(importJWKKMAC))
	ecdsaObj.Set("ImportKey", js.FuncOf(importKeyKMAC))
	ecdsaObj.Set("ExportKey", js.FuncOf(exportKeyKMAC))
	ecdsaObj.Set("RemoveKey", js.FuncOf(removeKeyKMAC))
	ecdsaObj.Set("HasKey", js.FuncOf(hasKeyKMAC))
}

func generateKeyKMAC(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	keySize := args[0].Int()

	data, err := kmac.GenerateKey(keySize)
	if err != nil {
		return errorToJS(err)
	}

	return data
}

func signJWKKMAC(this js.Value, args []js.Value) any {
	return nil
}

func verifyJWKKMAC(this js.Value, args []js.Value) any {
	return nil
}

func importJWKKMAC(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeObject}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	raw := map[string][]byte{}
	jsObj := args[0]

	l := []string{"k"}
	for _, v := range l {
		err = decodeB64(v, &jsObj, &raw)
		if err != nil {
			return errorToJS(err)
		}
	}

	result, err := kmac.ImportJWK(&raw)
	if err != nil {
		return errorToJS(err)
	}

	return result
}

func importKeyKMAC(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	val := args[0]

	var data []byte

	isString := isString(val)
	if isString {
		data = []byte(val.String())
	} else {
		data, err = toNative(val)
	}

	if err != nil {
		return errorToJS(err)
	}

	result, err := kmac.ImportKey(data)

	if err != nil {
		return errorToJS(err)
	}

	return result

}

func exportKeyKMAC(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeNumber}
	_, err := validateJSArgs(args, types, []int{1, 3})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	fmt := getAsInt(&args, 1, int(lib.FormatRaw))

	data, err := kmac.ExportKey(id, lib.Format(fmt))
	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyKMAC(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	return kmac.RemoveKey(id)
}

func hasKeyKMAC(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	return kmac.HasKey(id)
}
