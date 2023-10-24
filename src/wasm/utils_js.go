//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */

package wasm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"syscall/js"
	"wasm/cryptowasm/src/lib"
)

const (
	TypeUint8Array js.Type = 99
)

var uint8array = js.Global().Get("Uint8Array")

func InitRoot(name string) js.Value {
	return initChild(name, js.Global())
}

func initChild(name string, root js.Value) js.Value {
	obj := map[string]any{}
	root.Set(name, js.ValueOf(obj))
	return root.Get(name)
}

func isBool(val js.Value) bool {
	return val.Type() == js.TypeBoolean
}

func isNumber(val js.Value) bool {
	return val.Type() == js.TypeNumber
}

func isString(val js.Value) bool {
	return val.Type() == js.TypeString
}

func isUint8Array(val js.Value) bool {
	return val.InstanceOf(uint8array)
}

func toNative(val js.Value) ([]byte, error) {

	isString := isString(val)
	isUint8Array := isUint8Array(val)

	var data []byte = nil

	if isUint8Array {
		inBuf := make([]uint8, val.Length())
		js.CopyBytesToGo(inBuf, val)
		data = []byte(inBuf)
	} else if isString {
		data = []byte(val.String())
	}

	if data == nil {
		return nil, errors.New(lib.ERR_ARRAY_CONVERT)
	}

	return data, nil
}

func bytesToJS(data []byte) any {
	result := uint8array.New(len(data))
	js.CopyBytesToJS(result, data)
	return result
}

// errorToJS convert GO error|string to js.Value
func errorToJS(err any) js.Value {
	e, ok := err.(error)
	val := ""
	if ok {
		if e == nil {
			return js.Null()
		}
		val = err.(error).Error()
	} else {
		val = err.(string)
	}
	return js.ValueOf(map[string]any{"error": val})
}

func getAsBool(args *[]js.Value, id int, dft bool) bool {
	if len(*args) < id+1 {
		return dft
	}
	return (*args)[id].Bool()
}

func getAsInt(args *[]js.Value, id int, dft int) int {
	if len(*args) < 1+1 {
		return dft
	}
	return (*args)[id].Int()
}

func validateJSArgs(args []js.Value, types []js.Type, lengths []int) (int, error) {

	alen := len(args)
	tlen := len(types)

	_, max := findMinAndMax(lengths)
	if tlen < max {
		return alen, errors.New(lib.ERR_INVALID_ARGS_VALIDATION)
	}

	el := contains(lengths, alen)
	if el == 0 {
		if alen >= tlen {
			el = tlen
		}
	}

	if el == 0 {
		return alen, errors.New(lib.ERR_INVALID_ARGS)
	}

	var list []string
	for i, t := range types[:el] {

		c := args[i].Type()
		ok := c == t

		if t == TypeUint8Array {
			ok = isString(args[i]) || isUint8Array(args[i])
		}

		if !ok {
			msg := fmt.Sprintf("arg(%d), type: %s, expected: %s", i, c.String(), t.String())
			list = append(list, msg)
		}
	}

	if len(list) > 0 {
		msg := strings.Join(list, "\n")
		return alen, fmt.Errorf("%s >> %s", lib.ERR_INVALID_ARGS, msg)
	}

	return alen, nil
}

// findMinAndMax finds smallest and bigest value in array
func findMinAndMax(a []int) (min int, max int) {

	if len(a) == 0 {
		return 0, 0
	}

	min = a[0]
	max = a[0]

	for _, value := range a {

		if value < min {
			min = value
		}

		if value > max {
			max = value
		}

	}

	return min, max
}

// contains check if value exist in array
func contains(s []int, val int) int {
	for _, v := range s {
		if v == val {
			return v
		}
	}
	return 0
}

func decodeB64(key string, jsObj *js.Value, data *map[string][]byte) error {

	val := jsObj.Get(key)

	if val.Type() == js.TypeString {

		v, err := base64.RawURLEncoding.DecodeString(val.String())
		if err != nil {
			return err
		}

		(*data)[key] = v
	}

	return nil
}
