# CryptoWasm 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

**NOTE** This is experimental, not for production use. 

CryptoWasm is a WebAssemby drop-in replacement for native CryptoSubtle when encryption is required on non-https websites.

Source is written in GO and compiled as WASM, JavaScript modules are integration wrapper used as a drop-in replacement for browser native CryptoAPi.

For implemented Web Crypto API fetures, please refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto.

 - WrapKey/UnwrapKey is not implemented
 - other algos are fully implemented
 - JS Code is a drop in replacement for crypto.subtle 
 - key storage security is not high compared to native crypto.subtle
 - all input data can be Uint8Array or String (automatically converted to byte array) 

## Compilation

- Code uses ECDH - requires Go 1.20

- Last TinyGo 0.27 is required for minimal WASM size

- TinyGo memory management does not clean up object references. 

- TinyGo version not usable in some cases with long lasting web pages (SPA).

To see how to compile in GO and TinyGo, check __.bat__ files

## Using CryptoWasm functions

Check [Quickstart](Quickstart.md).

&copy; Green Screens Ltd. 2016 - 2023
