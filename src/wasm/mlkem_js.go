//go:build js && wasm

/*
 * Copyright (C) 2015, 2026 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptowasm/src/lib"
	"wasm/cryptowasm/src/mlkem"
)

// README https://wicg.github.io/webcrypto-modern-algos/#ml-kem

// InitMlKem registers the ML-KEM engine on globalThis.CryptoWasm.
func InitMlKem(root js.Value) {
	mlkemObj := initChild("mlkem", root)
	mlkemObj.Set("GenerateKey", js.FuncOf(generateKeyMLKEM))
	mlkemObj.Set("Encapsulate", js.FuncOf(encapsulateMLKEM))
	mlkemObj.Set("Decapsulate", js.FuncOf(decapsulateMLKEM))
	mlkemObj.Set("ImportJWK", js.FuncOf(importJWKMLKEM))
	mlkemObj.Set("ImportKey", js.FuncOf(importKeyMLKEM))
	mlkemObj.Set("ExportKey", js.FuncOf(exportKeyMLKEM))
	mlkemObj.Set("RemoveKey", js.FuncOf(removeKeyMLKEM))
	mlkemObj.Set("HasKey", js.FuncOf(hasKeyMLKEM))
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

	types := []js.Type{js.TypeString}
	_, err := validateJSArgs(args, types, []int{1})
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

	types := []js.Type{js.TypeString, TypeUint8Array}
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

	types := []js.Type{js.TypeObject, js.TypeString}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	raw := map[string][]byte{}
	jsObj := args[0]

	for _, field := range []string{"priv", "pub"} {
		value := jsObj.Get(field)
		if value.Type() == js.TypeString {
			raw[field] = []byte(value.String())
		}
	}

	algorithm := jsObj.Get("alg").String()
	if algorithm == "" {
		algorithm = jsObj.Get("crv").String()
	}
	if len(args) > 1 {
		algorithm = args[1].String()
	}
	result, err := mlkem.ImportJWK(&raw, algorithm)
	if err != nil {
		return errorToJS(err)
	}

	return result
}

func importKeyMLKEM(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, js.TypeBoolean, js.TypeString}
	_, err := validateJSArgs(args, types, []int{1, 2, 3})
	if err != nil {
		return errorToJS(err)
	}

	val := args[0]
	isPub := getAsBool(&args, 1, false)
	algorithm := ""
	if len(args) > 2 {
		algorithm = args[2].String()
	}

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
		data, err = mlkem.ImportPrivateKey(data, algorithm)
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
