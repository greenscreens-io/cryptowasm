# Quickstart

To use CryptoWASM as a drop-in replacement for **globalThis.crypto.subtle** when not available, use code example below.

NOTE: globalThis.crypto.subtle is not available under HTTP protocol.

```javascript
// prepare file paths
globalThis.CRYPTO_WASM = '/lib';
globalThis.CRYPTO_GO = '/lib';

import CryptoJSWasm from './lib/WasmLoader.mjs'
import CryptoJS from './lib/CryptoJS.mjs'

// load and initialize wasm module
await CryptoJSWasm.init();

// to override browser native module as a drop-in replacement.
globalThis.crypto.subtle = new CryptoJS();
```

---

# Using WebAssebly only

To use WebAssebly module CryptoWasm only without drop-in replacement, use example below to initialize. 

```javascript
// prepare file paths
globalThis.CRYPTO_WASM = '/lib';
globalThis.CRYPTO_GO = '/lib';

import CryptoJSWasm from './lib/WasmLoader.mjs'
await CryptoJSWasm.init();
```

globalThis.CryptoWasm will be available after initialization with CryptoJSWasm.init. 
Check examples below or refer to GO code or CryptoJS.mjs / CryptoKeyJS.mjs to see how CryptoWasm is used internaly.
All CryptoWasm calls are synchronous. Async mode is emulated through CryptoJS.mjs drop-in replacement to have 1-to-1 mapping to the native browser implemetation.


## Using random functions
<hr>

Wasm implementation
```javascript
CryptoWasm.random(16)
```

Native implementation
```javascript
d = new Uint8Array(16)
crypto.getRandomValues(d)
```

## Using SHA-x functions
<hr>

Wasm implementation
```javascript
let  data = 'The quick brown fox jumps over the lazy dog';
CryptoWasm.Sha1(data)
CryptoWasm.Sha224(data)
CryptoWasm.Sha256(data)
CryptoWasm.Sha384(data)
CryptoWasm.Sha512(data)

```

Native implementation
```javascript
let  data = 'The quick brown fox jumps over the lazy dog';
raw = new TextEncoder().encode(data)
hash = await crypto.subtle.digest('SHA-1', raw);
res = new Uint8Array(hash)
```

## Using HMAC functions
<hr>

SHA-1 = 512 bit<br>
SHA-256 = 512 bit<br>
SHA-384 = 1024 bit<br>
SHA-512 = 1024 bit<br>

length:512 = 64bytes<br>
length:1024 = 128bytes<br>
length:2048 = 256bytes<br>

Wasm implementation
```javascript
let  data = 'The quick brown fox jumps over the lazy dog';
data = new TextEncoder().encode(data)
key = CryptoWasm.random(512/8)
sign = CryptoWasm.Hmac384Sign(data, key)
CryptoWasm.Hmac384Verify(data, sign, key)

```

Native implementation
```javascript
let  data = 'The quick brown fox jumps over the lazy dog';
k = await crypto.subtle.generateKey({name:'HMAC', hash:'SHA-384', length:1024}, true, ['sign', 'verify'])
d = await crypto.subtle.exportKey('raw', k)

data = new TextEncoder().encode(data)

s = await crypto.subtle.sign('HMAC', k, data)
await crypto.subtle.verify('HMAC', k, s, data)

// convert for CryptoJSWasm - to comapre
key = new Uint8Array(d)
sign = new Uint8Array(s)
CryptoWasm.toHex(sign)

```

## Using AES functions
<hr>

Wasm implementation
```javascript
txt = 'The quick brown fox jumps over the lazy dog';
key = '12345678123456781234567812345678'
iv = '1234567812345678'

d = CryptoWasm.CTREncrypt(key, txt, iv)
t = CryptoWasm.CTRDecrypt(key, d, iv)

d = CryptoWasm.CBCEncrypt(key, txt, iv)
t = CryptoWasm.CBCDecrypt(key, d, iv)

iv = '123456781234'
d = CryptoWasm.GCMEncrypt(key, txt, iv)
t = CryptoWasm.GCMDecrypt(key, d, iv)
new TextDecoder().decode(t)
```

Native implementation 
```javascript
let  data = 'The quick brown fox jumps over the lazy dog';
k = await crypto.subtle.generateKey({name:'AES-CTR', length:256}, true, ['encrypt', 'decrypt'])
d = await crypto.subtle.exportKey('raw', k)

key = new Uint8Array(d)
data = new TextEncoder().encode(data)

cnt = new Uint8Array(16)
crypto.getRandomValues(d)

r = await crypto.subtle.encrypt({name:'AES-CTR', length:64, counter : cnt}, k, data)
res = new uint8Array(r)
```

## Using ECDHA functions
<hr>

Valid sizes: 256, 384, 521

Wasm implementation
```javascript
let data = 'The quick brown fox jumps over the lazy dog';
data = new TextEncoder().encode('lazy fox jumps over')

// generate private key
id = CryptoWasm.ecdsa.GenerateKey(256)
CryptoWasm.ecdsa.HasKey(id)

s = CryptoWasm.ecdsa.Sign(id, data)
CryptoWasm.ecdsa.Verify(id, data, s)

// not supported yet by TinyGO
CryptoWasm.ecdsa.ExportKey(id, true)
```

Native implementation
```javascript
k = await crypto.subtle.generateKey({name:'ECDSA', namedCurve: "P-384"}, true, ['sign', 'verify'])
pub = await crypto.subtle.exportKey('raw', k.publicKey)
priv = await crypto.subtle.exportKey('pkcs8', k.privateKey)
btoa(new Uint8Array(pub))
btoa(new Uint8Array(priv))

```

## Using HKDF

Password can be any string, salt byte length must be one of SHA-x algo byte length (20,28,32,48,64)

Wasm implementation
```javascript
let data = 'The quick brown fox jumps over the lazy dog';
id = CryptoWasm.hkdf.GenerateMaster(data, "12345678123456781234567812345678")
CryptoWasm.hkdf.GenerateKey(id, 16)
CryptoWasm.hkdf.GenerateKey(id, 16, true)
```

## Using PBKDF2

Salt must be multiple of 8; hash must be bit or byte length of sha-x algo 

CryptoWasm.GeneratePBKDF2(pwd, salt, iter, keyLen, hash(bit|byte len))

Wasm implementation
```javascript
let data = 'The quick brown fox jumps over the lazy dog';
CryptoWasm.GeneratePBKDF2(data, "123456781234567812345678", 1000, 16, 64)
```