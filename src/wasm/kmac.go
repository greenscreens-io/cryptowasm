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
	kmacObj := initChild("kmac", root)
	kmacObj.Set("GenerateKey", js.FuncOf(generateKeyKMAC))
	kmacObj.Set("Sign", js.FuncOf(signKMAC))
	kmacObj.Set("Verify", js.FuncOf(verifyKMAC))
	kmacObj.Set("ImportJWK", js.FuncOf(importJWKKMAC))
	kmacObj.Set("ImportKey", js.FuncOf(importKeyKMAC))
	kmacObj.Set("ExportKey", js.FuncOf(exportKeyKMAC))
	kmacObj.Set("RemoveKey", js.FuncOf(removeKeyKMAC))
	kmacObj.Set("HasKey", js.FuncOf(hasKeyKMAC))
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

func signKMAC(this js.Value, args []js.Value) any {
	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, js.TypeNumber, TypeUint8Array}
	_, err := validateJSArgs(args, types, []int{3, 4})
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	var result []byte
	if len(args) == 4 {
		customization, err := toNative(args[3])
		if err != nil {
			return errorToJS(err)
		}
		result, err = kmac.Sign(args[0].String(), data, args[2].Int(), customization)
	} else {
		result, err = kmac.Sign(args[0].String(), data, args[2].Int())
	}
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func verifyKMAC(this js.Value, args []js.Value) any {
	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, TypeUint8Array, TypeUint8Array}
	_, err := validateJSArgs(args, types, []int{3, 4})
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	tag, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	var valid bool
	if len(args) == 4 {
		customization, err := toNative(args[3])
		if err != nil {
			return errorToJS(err)
		}
		valid, err = kmac.Verify(args[0].String(), data, tag, customization)
	} else {
		valid, err = kmac.Verify(args[0].String(), data, tag)
	}
	if err != nil {
		return errorToJS(err)
	}

	return valid
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
