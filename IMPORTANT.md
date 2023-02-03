## TINYGO issues 
--------

TinyGO makes wasm significantly smaller than GO WASM, however, issues noticed 

- does not fully support reflect, making program break on export/import while parsing ASN1
  https://github.com/tinygo-org/tinygo/pull/2479/files

- memory leaks
  https://github.com/tinygo-org/tinygo/issues/1140

- ECDH algorithm supported from GO 1.20; currently not supported version by TinyGO 0.26 compiler.

## Algorithms
____

Future browser support for Ed25519 and Ed448
-------
https://github.com/WICG/webcrypto-secure-curves/blob/main/explainer.md
https://sites.google.com/a/chromium.org/dev/blink/webcrypto

ECDH + KHDF
-------
https://stackoverflow.com/questions/67938461/web-cryptography-implement-hkdf-for-the-output-of-ecdh

PBKDF2
-------
https://medium.com/coinmonks/fun-times-with-webcrypto-part-1-pbkdf2-815b1c978c9d

JWK
-------
https://www.rfc-editor.org/rfc/rfc7517#section-8.1
https://www.rfc-editor.org/rfc/rfc7518
https://www.rfc-editor.org/rfc/rfc8037#appendix-A

JWK use bas64url = base64 with replacements 
byte base64  base64url
62     +       -
63     /       _

equal(=) can be eliminated

-----
https://github.com/WICG/web-smart-card

https://pkg.go.dev/github.com/gowebapi/webapi


