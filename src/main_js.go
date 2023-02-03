//go:build wasm

/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package main

import (
	"wasm/cryptojs/src/wasm"
)

// main initialization point for WASm,
// will register internal object to the browser globalThis.CryptoWasm
// all sub-objects will be attached as child objects references
func main() {
	done := make(chan struct{})
	root := wasm.InitRoot("CryptoWasm")
	wasm.InitGC(root)
	wasm.InitUtil(root)
	wasm.InitRand(root)
	wasm.InitHash(root)
	wasm.InitHKDF(root)
	wasm.InitPBKDF2(root)
	wasm.InitHmac(root)
	wasm.InitAES(root)
	wasm.InitRsa(root)
	wasm.InitEcdsa(root)
	wasm.InitEcdh(root)
	wasm.InitED25519(root)
	<-done
}
