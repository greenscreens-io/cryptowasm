//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptowasm/src/lib"
	"wasm/cryptowasm/src/mlkem"
)

// README https://wicg.github.io/webcrypto-modern-algos/#ml-kem

// InitMlKem register ecdsa engine to the globalThis.CryptoWasm
func InitMlKem(root js.Value) {
	ecdsaObj := initChild("mlkem", root)
	ecdsaObj.Set("GenerateKey", js.FuncOf(generateKeyMLKEM))
	ecdsaObj.Set("Encapsulate", js.FuncOf(encapsulateMLKEM))
	ecdsaObj.Set("Decapsulate", js.FuncOf(decapsulateMLKEM))
	ecdsaObj.Set("ImportJWK", js.FuncOf(importJWKMLKEM))
	ecdsaObj.Set("ImportKey", js.FuncOf(importKeyMLKEM))
	ecdsaObj.Set("ExportKey", js.FuncOf(exportKeyMLKEM))
	ecdsaObj.Set("RemoveKey", js.FuncOf(removeKeyMLKEM))
	ecdsaObj.Set("HasKey", js.FuncOf(hasKeyMLKEM))
}

func generateKeyMLKEM(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	keySize := args[0].Int()

	data, err := mlkem.GenerateKey(keySize)
	if err != nil {
		return errorToJS(err)
	}

	return data
}

// pubKeyID
func encapsulateMLKEM(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeString, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	pubKeyID := args[0].String()
	sharedSecret, cipherText, err := mlkem.Encapsulate(pubKeyID)
	if err != nil {
		return errorToJS(err)
	}

	sharedSecretJS := bytesToJS(sharedSecret)
	cipherTextJS := bytesToJS(cipherText)

	return js.ValueOf(map[string]any{"sharedSecret": sharedSecretJS, "cipherText": cipherTextJS})
}

// privKeyID, cipertext
func decapsulateMLKEM(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeString}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	privKeyID := args[0].String()
	val := args[1]

	var cypherText []byte

	isString := isString(val)
	if isString {
		cypherText = []byte(val.String())
	} else {
		cypherText, err = toNative(val)
	}

	if err != nil {
		return errorToJS(err)
	}

	sharedSecret, err := mlkem.Decapsulate(privKeyID, cypherText)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(sharedSecret)
}

func importJWKMLKEM(this js.Value, args []js.Value) any {

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

	result, err := mlkem.ImportJWK(&raw, jsObj.Get("crv").String())
	if err != nil {
		return errorToJS(err)
	}

	return result
}

func importKeyMLKEM(this js.Value, args []js.Value) any {

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
		data, err = mlkem.ImportPublicKey(data)
	} else {
		data, err = mlkem.ImportPrivateKey(data)
	}

	if err != nil {
		return errorToJS(err)
	}

	return data

}

func exportKeyMLKEM(this js.Value, args []js.Value) any {

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
		data, err = mlkem.ExportPublicKey(id, lib.Format(fmt))
	} else {
		data, err = mlkem.ExportPrivateKey(id, lib.Format(fmt))
	}

	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyMLKEM(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return mlkem.RemoveKey(id, isPublic)
}

func hasKeyMLKEM(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return mlkem.HasKey(id, isPublic)
}
