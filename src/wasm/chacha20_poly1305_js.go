//go:build js && wasm

/*
 * Copyright (C) 2015, 2026 Green Screens Ltd.
 */
package wasm

// README https://wicg.github.io/webcrypto-modern-algos/#chacha20-poly1305

import (
	"syscall/js"
	"wasm/cryptowasm/src/chachapoly"
	"wasm/cryptowasm/src/lib"
)

// InitChaChaPoly registers ChaCha20-Poly1305 on globalThis.CryptoWasm.
func InitChaChaPoly(root js.Value) {
	chachaObj := initChild("chacha20poly1305", root)
	chachaObj.Set("GenerateKey", js.FuncOf(generateKeyCHACHAPOLY))
	chachaObj.Set("Encrypt", js.FuncOf(encryptCHACHAPOLY))
	chachaObj.Set("Decrypt", js.FuncOf(decryptCHACHAPOLY))
	chachaObj.Set("ImportJWK", js.FuncOf(importJWKCHACHAPOLY))
	chachaObj.Set("ImportKey", js.FuncOf(importKeyCHACHAPOLY))
	chachaObj.Set("ExportKey", js.FuncOf(exportKeyCHACHAPOLY))
	chachaObj.Set("RemoveKey", js.FuncOf(removeKeyCHACHAPOLY))
	chachaObj.Set("HasKey", js.FuncOf(hasKeyCHACHAPOLY))
}

func generateKeyCHACHAPOLY(this js.Value, args []js.Value) any {

	gc_wait = true

	data, err := chachapoly.GenerateKey()
	if err != nil {
		return errorToJS(err)
	}

	return data
}

// keyID, nonce(12), tag(128) additionalData
func encryptCHACHAPOLY(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, TypeUint8Array, TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()

	nonce, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	tag, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[3])
	if err != nil {
		return errorToJS(err)
	}

	result, err := chachapoly.Encrypt(id, nonce, tag, data)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func decryptCHACHAPOLY(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, TypeUint8Array, TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()

	nonce, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	tag, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	data, err := toNative(args[3])
	if err != nil {
		return errorToJS(err)
	}

	result, err := chachapoly.Decrypt(id, nonce, tag, data)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)

}

func importJWKCHACHAPOLY(this js.Value, args []js.Value) any {

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

	result, err := chachapoly.ImportJWK(&raw)
	if err != nil {
		return errorToJS(err)
	}

	return result
}

func importKeyCHACHAPOLY(this js.Value, args []js.Value) any {

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

	result, err := chachapoly.ImportKey(data)

	if err != nil {
		return errorToJS(err)
	}

	return result

}

func exportKeyCHACHAPOLY(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeNumber}
	_, err := validateJSArgs(args, types, []int{1, 3})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	fmt := getAsInt(&args, 1, int(lib.FormatRaw))

	data, err := chachapoly.ExportKey(id, lib.Format(fmt))
	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyCHACHAPOLY(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	return chachapoly.RemoveKey(id)
}

func hasKeyCHACHAPOLY(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	return chachapoly.HasKey(id)
}
