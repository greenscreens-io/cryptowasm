//go:build js && wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package wasm

import (
	"runtime"
	"syscall/js"
)

/*
 * This module implements Browser shcheduled GO GC every second to keep from memory growth.
 */

var gc_wait = false
var gc_pause = 0
var iid = 0

// InitGC register wasm GC for internal JavaScript integration module,
// GO GC must be called peridically from the browser to clear wasm memory
func InitGC(root js.Value) {
	root.Set("GC", js.FuncOf(gcJS))
	root.Set("GCPause", js.FuncOf(gcPauseJS))
	root.Set("GCToken", js.FuncOf(gcTokenJS))
	iid = js.Global().Call("setInterval", js.FuncOf(autoGC), 1000).Int()
}

func gcTokenJS(this js.Value, args []js.Value) any {
	return iid
}

func gcPauseJS(this js.Value, args []js.Value) any {

	if len(args) > 0 {

		if args[0].Type() == js.TypeBoolean {
			gc_pause = 5
		}

		if args[0].Type() == js.TypeNumber {
			gc_pause = args[0].Int()
		}

	}

	return gc_pause
}

func gcJS(this js.Value, args []js.Value) any {
	runtime.GC()
	gc_wait = false
	gc_pause = 0
	return js.Undefined()
}

func autoGC(this js.Value, args []js.Value) any {

	if gc_pause > 0 {
		gc_pause--
	}

	if gc_pause == 0 && gc_wait {
		runtime.GC()
	}

	return js.Undefined()
}
