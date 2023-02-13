import CryptoJSWasm from './modules/WasmLoader.mjs'
import CryptoJS from './modules/CryptoJS.mjs'

globalThis.CRYPTO_WASM = '/release';
globalThis.CRYPTO_GO = '/release';

await CryptoJSWasm.init();

globalThis.CryptoJS = new CryptoJS();

const r = await fetch('/jwk/jwk_wasm.json')
globalThis.jwk = await r.json()

function importWasm(name, kp) {
  let alg = null
  if (name.indexOf('RSA') == 0) {
	alg = globalThis.CryptoWasm.rsa;
  } else if (name.indexOf('ECDH') == 0) {
	alg = globalThis.CryptoWasm.ecdh;
  } else if (name.indexOf('ECDSA') == 0) {
	alg = globalThis.CryptoWasm.ecdsa;
  }
  try {
    kp.privateKey.id = alg.ImportJWK(kp.privateKey);
  } catch (e) {
    console.log(`Private key import for ${JSON.stringify(kp)}`);
    console.log(e);
  }
  try {
    kp.publicKey.id = alg.ImportJWK(kp.publicKey);
  } catch (e) {
    console.log(`Public key import for ${JSON.stringify(kp)}`);
    console.log(e);
  }
}

Object.entries(jwk).filter(kv => kv[1].privateKey).forEach(kv => importWasm(kv[0], kv[1]));

const msg = 'brown fox jumps over lazy dog'
let egine, key, sgn, sts, enc, dec, res;

egine = globalThis.CryptoWasm.rsa
key = jwk['RSA-OAEP_SHA-1_1024']
enc = egine.Encrypt(key.publicKey.id, 256, msg)
dec = egine.Decrypt(key.privateKey.id, 256, enc)
dec = new TextDecoder().decode(dec)
console.assert(dec === msg, key)

egine = globalThis.CryptoWasm.rsa
key = jwk['RSA-PSS_SHA-1_1024']
sgn = egine.SignPSS(key.privateKey.id, msg, 20, 20)
sts = egine.VerifyPSS(key.publicKey.id, msg, sgn, 20, 20)
console.assert(sts, key)

egine = globalThis.CryptoWasm.rsa
key = jwk['RSASSA-PKCS1-v1_5_SHA-256_1024']
sgn = egine.SignPKCS1v15(key.privateKey.id, msg, 256)
sts = egine.VerifyPKCS1v15(key.publicKey.id, msg, sgn, 256)
console.assert(sts, key)

egine = globalThis.CryptoWasm.ecdsa
key = jwk['ECDSA_P-256']
sgn = egine.Sign(key.privateKey.id, msg, 0)
sts = egine.Verify(key.publicKey.id, msg, sgn, 0)
console.assert(sts, key)

egine = globalThis.CryptoWasm.ecdh
key = jwk['ECDH_P-256']
res = egine.DeriveKey(key.privateKey.id, key.publicKey.id, 128)
console.assert(res.error == null, key)
