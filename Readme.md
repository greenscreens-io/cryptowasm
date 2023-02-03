# CryptoWasm 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

**NOTE** This is experimental, not for production use. 

CryptoWasm is a WebAssemby drop-in replacement for native CryptoSubtle when encryption is required on non-https websites.

Source is written in GO to support encryption algorthms, JavaScript modules are integration wrapper used as a drop-in replacement for browser native CraptoAPi.

For Web Crypto API fetures implemented, please refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto.

 - WrapKey/UnwrapKey is not implemented
 - other algos are fully implemented
 - JS Code is a drop in replacement for crypto.subtle 
 - key storage security is not high compared to native crypto.subtle
 - all input data can be Uint8Array or string (automatically converted to byte array) 

## Compilation

Code uses ECDH - requires Go 1.20
Last TinyGo 0.26 does not support full reflection, key export to PEM does not work 
Last TinyGo 0.26 does not support Go 1.20, not possible to compile.

To see how to compile in GO and TinyGo, check __.bat__ files

## Using CryptoWasm functions

Check [Quickstart](Quickstart.md).

&copy; Green Screens Ltd. 2016 - 2023
