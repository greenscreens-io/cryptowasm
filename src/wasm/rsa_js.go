//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"syscall/js"
	"wasm/cryptowasm/src/lib"
	"wasm/cryptowasm/src/rsa"
)

// InitRsa register rsa engine to the globalThis.CryptoWasm
func InitRsa(root js.Value) {
	rsaObj := initChild("rsa", root)
	rsaObj.Set("GenerateKey", js.FuncOf(generateKeyRSAJS))
	rsaObj.Set("ImportJWK", js.FuncOf(importJWKRSAJS))
	rsaObj.Set("ImportKey", js.FuncOf(importKeyRSAJS))
	rsaObj.Set("ExportKey", js.FuncOf(exportKeyRSAJS))
	rsaObj.Set("RemoveKey", js.FuncOf(removeKeyRSAJS))
	rsaObj.Set("HasKey", js.FuncOf(hasKeyRSAJS))
	rsaObj.Set("Encrypt", js.FuncOf(encryptRSAJS))
	rsaObj.Set("Decrypt", js.FuncOf(decryptRSAJS))
	rsaObj.Set("SignPSS", js.FuncOf(signPSSRSAJS))
	rsaObj.Set("VerifyPSS", js.FuncOf(verifyPSSRSAJS))
	rsaObj.Set("SignPKCS1v15", js.FuncOf(signPKCS1v15JS))
	rsaObj.Set("VerifyPKCS1v15", js.FuncOf(verifyPKCS1v15JS))
}

func generateKeyRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeNumber, js.TypeNumber}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	size := args[0].Int()
	pex := getAsInt(&args, 1, 0)

	data, err := rsa.GenerateKey(size, pex)
	if err != nil {
		return errorToJS(err)
	}

	return data
}

func encryptRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeNumber, TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	size := args[1].Int()

	data, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	result, err := rsa.Encrypt(id, size, data)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func decryptRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeNumber, TypeUint8Array}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	size := args[1].Int()

	data, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	result, err := rsa.Decrypt(id, size, data)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func importJWKRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeObject}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	raw := map[string][]byte{}
	jsObj := args[0]

	l := []string{"e", "n", "d", "p", "q", "qi", "dp", "dq"}
	for _, v := range l {
		err = decodeB64(v, &jsObj, &raw)
		if err != nil {
			return errorToJS(err)
		}
	}

	result, err := rsa.ImportJWK(&raw)
	if err != nil {
		return errorToJS(err)
	}

	return result
}

func importKeyRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{TypeUint8Array, js.TypeBoolean}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	val := args[0]
	isPub := args[1].Bool()

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
		data, err = rsa.ImportPublicKey(data)
	} else {
		data, err = rsa.ImportPrivateKey(data)
	}

	if err != nil {
		return errorToJS(err)
	}

	return data
}

func exportKeyRSAJS(this js.Value, args []js.Value) any {

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
		data, err = rsa.ExportPublicKey(id, lib.Format(fmt))
	} else {
		data, err = rsa.ExportPrivateKey(id, lib.Format(fmt))
	}

	if err != nil {
		return errorToJS(err)
	}

	if lib.Format(fmt) == lib.FormatRaw {
		return bytesToJS(data.([]byte))
	}

	return data
}

func removeKeyRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return rsa.RemoveKey(id, isPublic)
}

func hasKeyRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, js.TypeBoolean}
	_, err := validateJSArgs(args, types, []int{1, 2})
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	isPublic := getAsBool(&args, 1, false)

	return rsa.HasKey(id, isPublic)
}

func signPSSRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, js.TypeNumber, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	hashLength := args[2].Int()
	saltLength := args[3].Int()
	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	result, err := rsa.SignPSS(id, data, hashLength, saltLength)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func verifyPSSRSAJS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, TypeUint8Array, js.TypeNumber, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	hashLength := args[3].Int()
	saltLength := args[4].Int()

	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	sign, err := toNative(args[2])
	if err != nil {
		return errorToJS(err)
	}

	err = rsa.VerifyPSS(id, data, sign, hashLength, saltLength)
	if err != nil {
		return errorToJS(err)
	}

	return true

}

func signPKCS1v15JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
	if err != nil {
		return errorToJS(err)
	}

	id := args[0].String()
	size := args[2].Int()
	data, err := toNative(args[1])
	if err != nil {
		return errorToJS(err)
	}

	result, err := rsa.SignPKCS1v15(id, data, size)
	if err != nil {
		return errorToJS(err)
	}

	return bytesToJS(result)
}

func verifyPKCS1v15JS(this js.Value, args []js.Value) any {

	gc_wait = true

	types := []js.Type{js.TypeString, TypeUint8Array, TypeUint8Array, js.TypeNumber}
	_, err := validateJSArgs(args, types, nil)
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

	err = rsa.VerifyPKCS1v15(id, data, sign, size)
	if err != nil {
		return errorToJS(err)
	}

	return true

}
