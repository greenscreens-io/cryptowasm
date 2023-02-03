/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
import CryptoKeyJS from './CryptoKeyJS.mjs';
import WasmLoader from './WasmLoader.mjs';

export default class CryptoJS {

    static RETURN_RAW = true;
    static #ERR_INVALID_ALG = 'Invalid alogrithm!';
    static #ERR_INVALID_FORMAT = 'Invalid format';
    static #ERR_UNSUPPORTED = 'Unsupported operation!';
    static #ERR_INVALID_KEY_ALG = 'Invalid key for algorithm';
    static #ERR_INVALID_SHA = 'Invalid SHA-x';

    get crypto() {
        globalThis.CryptoWasm.gc = true;
        return globalThis.CryptoWasm;
    }

    get asRaw() {
        return WasmLoader.RETURN_RAW === true;
    }

    #toUint8Array(data) {
        if (data instanceof Uint8Array) return data;
        if (data instanceof ArrayBuffer) return new Uint8Array(data);
        if (data instanceof DataView) return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
        if (data.buffer) return this.#toUint8Array(data.buffer);
        throw new Error('Invalid data type!');
    }

    #verify(format, expected) {
        if (expected.indexOf(format) < 0) throw new DOMException(CryptoJS.#ERR_INVALID_FORMAT);
    }

    #verifyAsync(format) {
        return this.#verify(format, ['pkcs8', 'spki', 'raw']);
    }

    #isPublic(format) {
        switch (format) {
            case 'pkcs8': return false;
            case 'spki':
            case 'raw':
                return true;
            default: throw new TypeError(CryptoJS.#ERR_INVALID_FORMAT);
        }
    }

    #importAsyncKey(format, keyData, algorithm, extractable, usages, cryptojs) {
        const me = this;
        me.#verifyAsync(format);
        const isPublic = me.#isPublic(format);
        const key = cryptojs.ImportKey(keyData, isPublic);
        return new CryptoKeyJS(algorithm, extractable, usages, key);
    }

    #importSyncKey(format, keyData, algorithm, extractable, usages) {
        this.#verify(format, ['raw']);
        return new CryptoKeyJS(algorithm, extractable, usages, keyData);
    }

    #generateKeyAES(algorithm, extractable, usages) {
        let key = null;
        switch (algorithm.length) {
            case 128:
            case 192:
            case 256:
                key = this.crypto.random(algorithm.length / 8);
                break;
            default: throw new Error('Invalid AES key length!');
        }
        return new CryptoKeyJS(algorithm, extractable, usages, key);
    }

    #generateKeyHMAC(algorithm, extractable, usages) {
        const size = algorithm.length || CryptoKeyJS.blockSize(algorithm.hash);
        const key = this.crypto.random(size / 8);
        return new CryptoKeyJS(algorithm, extractable, usages, key);
    }

    #generateKeyRSA(algorithm, extractable, usages) {
        let key = null;
        switch (algorithm.modulusLength) {
            case 1024:
            case 2048:
            case 4096:
                let pex = 0;
                algorithm.publicExponent?.forEach(v => pex = (pex << 8) + (v & 0xFF));
                key = this.crypto.rsa.GenerateKey(algorithm.modulusLength, pex);
                break;
            default: throw new Error('Invalid modulus length');
        }

        let pubu = null;
        let privu = null;
        if (algorithm.name === 'RSA-OAEP') {
            pubu = ['encrypt'];
            privu = ['decrypt'];
        } else {
            pubu = ['verify'];
            privu = ['sign'];
        }

        return {
            publicKey: new CryptoKeyJS(algorithm, extractable, pubu, key),
            privateKey: new CryptoKeyJS(algorithm, extractable, privu, key)
        };
    }

    #generateKeyEC(algorithm, cryptojs) {
        const size = CryptoKeyJS.curveSize(algorithm.namedCurve);
        return cryptojs.GenerateKey(size);
    }

    #generateSignKeyEC(algorithm, extractable, usages, obj) {
        const key = this.#generateKeyEC(algorithm, obj);
        return {
            publicKey: new CryptoKeyJS(algorithm, extractable, ['verify'], key),
            privateKey: new CryptoKeyJS(algorithm, extractable, ['sign'], key)
        };
    }

    #generateKeyECDSA(algorithm, extractable, usages) {
        const me = this;
        const obj = algorithm.namedCurve === 'Ed25519' ? me.crypto.ed25519 : me.crypto.ecdsa;
        return me.#generateSignKeyEC(algorithm, extractable, usages, obj);
    }

    // will be available in Go 1.20 February 2023.
    #generateKeyECDH(algorithm, extractable, usages) {
        const me = this;
        const key = me.#generateKeyEC(algorithm, me.crypto.ecdh);
        return {
            publicKey: new CryptoKeyJS(algorithm, extractable, [], key),
            privateKey: new CryptoKeyJS(algorithm, extractable, usages, key)
        };
    }

    #verifyName(algorithm, key) {
        const name = algorithm.name || algorithm;
        const keyName = key.algorithm.name || key.algorithm;
        if (name != keyName) throw new Error(CryptoJS.#ERR_INVALID_KEY_ALG);
    }

    randomUUID() {
        const raw = new Uint8Array(16);
        crypto.getRandomValues(raw);
        const s = this.crypto.toHex(raw).match(/.{2}/g);
        if (typeof s?.error === 'string') throw new Error(s.error);
        return 'xxxx-xx-xx-xx-xxxxxx'.split('').map(v => v === '-' ? v : s.pop()).join('');
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * @param {*} algorithm 
     * @param {*} key 
     * @param {*} data 
     */
    async decrypt(algorithm, key, data) {
        const me = this;
        me.#verifyName(algorithm, key);
        data = me.#toUint8Array(data)
        let iv = algorithm.iv || algorithm.counter;
        if (iv) iv = me.#toUint8Array(iv);
        const res = (key.privateKey || key).decrypt(data, iv);
        if (typeof res?.error === 'string') throw new Error(res.error);
        return me.asRaw ? res.buffer : res;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * @param {*} algorithm 
     * @param {*} baseKey 
     * @param {*} length 
     */
    async deriveBits(algorithm, baseKey, length) {
        const me = this;
        me.#verifyName(algorithm, baseKey);
        const res = baseKey.deriveBits(algorithm, length);
        if (typeof res?.error === 'string') throw new Error(res.error);
        return me.asRaw ? res.buffer : res;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * @param {*} algorithm 
     * @param {*} baseKey 
     * @param {*} derivedKeyAlgorithm 
     * @param {*} extractable 
     * @param {*} keyUsages 
     */
    async deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages) {
        const me = this;
        me.#verifyName(algorithm, key);
        algorithm.salt = me.#toUint8Array(algorithm.salt);
        const res = baseKey.deriveKey(algorithm, derivedKeyAlgorithm, extractable, keyUsages);
        if (typeof res?.error === 'string') throw new Error(res.error);
        return res;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * @param {*} algorithm 
     * @param {*} data 
     */
    async digest(algorithm, data) {

        const me = this;
        const hash = me.crypto.hash;

        data = me.#toUint8Array(data);

        let res = null;
        switch (algorithm) {
            case 'SHA-1':
                res = hash.Sha1(data);
                break;
            case 'SHA-256':
                res = hash.Sha256(data);
                break;
            case 'SHA-384':
                res = hash.Sha384(data);
                break;
            case 'SHA-512':
                res = hash.Sha512(data);
                break;
            default:
                throw new Error(CryptoJS.#ERR_INVALID_SHA);
        }
        if (typeof res?.error === 'string') throw new Error(res.error);
        return me.asRaw ? res.buffer : res;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * @param {*} algorithm 
     * @param {*} key 
     * @param {*} data 
     */
    async encrypt(algorithm, key, data) {
        const me = this;
        me.#verifyName(algorithm, key);
        data = me.#toUint8Array(data)
        let iv = algorithm.iv || algorithm.counter;
        if (iv) iv = me.#toUint8Array(iv);
        const res = (key.publicKey || key).encrypt(data, iv);
        if (typeof res?.error === 'string') throw new Error(res.error);
        return me.asRaw ? res.buffer : res;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * NOTE: Not available in tinygo builds (reflection issues)
     * Potentially custom build might help with this fix
     * https://github.com/tinygo-org/tinygo/pull/2479/files
     * @param {*} format 
     * @param {*} key 
     */
    async exportKey(format, key) {
        const res = key.export(format);
        if (typeof res?.error === 'string') throw new Error(res.error);
        if (format === 'jwk') return res;
        return this.asRaw ? res.buffer : res;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * @param {*} algorithm 
     * @param {*} extractable 
     * @param {*} keyUsages 
     */
    async generateKey(algorithm, extractable, keyUsages) {

        const me = this;
        let res = null
        switch (algorithm.name) {
            case 'Ed25519':
            case 'ECDSA':
                res = me.#generateKeyECDSA(algorithm, extractable, keyUsages);
                break;
            case 'X25519':
            case 'ECDH':
                res = me.#generateKeyECDH(algorithm, extractable, keyUsages);
                break;
            case 'RSASSA-PKCS1-v1_5':
            case 'RSA-OAEP':
            case 'RSA-PSS':
                res = me.#generateKeyRSA(algorithm, extractable, keyUsages);
                break;
            case 'HMAC':
                res = me.#generateKeyHMAC(algorithm, extractable, keyUsages);
                break;
            case 'AES-CBC':
            case 'AES-CTR':
            case 'AES-GCM':
                res = me.#generateKeyAES(algorithm, extractable, keyUsages);
                break;
            default: throw new Error(CryptoJS.#ERR_INVALID_ALG);
        }
        if (typeof res?.error === 'string') throw new Error(res.error);
        return res;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * NOTE: Not available in tinygo builds (reflection issues)
     * @param {*} format 
     * @param {*} keyData 
     * @param {*} algorithm 
     * @param {*} extractable 
     * @param {*} keyUsages 
     */
    async importKey(format, keyData, algorithm, extractable, keyUsages) {
        const me = this;
        keyData = me.#toUint8Array(keyData);
        const name = algorithm.name || algorithm;
        const wasm = me.crypto;
        let res = null;
        switch (name) {
            case 'AES-CBC':
            case 'AES-CTR':
            case 'AES-GCM':
            case 'HMAC':
            case 'PBKDF2':
            case 'HKDF':
                res = me.#importSyncKey(format, keyData, algorithm, extractable, keyUsages);
                break;
            case 'RSASSA-PKCS1-v1_5':
            case 'RSA-OAEP':
            case 'RSA-PSS':
                res = me.#importAsyncKey(format, keyData, algorithm, extractable, keyUsages, wasm.rsa);
                break;
            case 'ECDSA':
                res = me.#importAsyncKey(format, keyData, algorithm, extractable, keyUsages, wasm.ecdsa);
                break;
            case 'ECDH':
                res = me.#importAsyncKey(format, keyData, algorithm, extractable, keyUsages, wasm.ecdh);
                break;
            case 'Ed25519':
                res = me.#importAsyncKey(format, keyData, algorithm, extractable, keyUsages, wasm.ed25519);
                break;
            default: throw new Error(CryptoJS.#ERR_INVALID_ALG);
        }
        if (typeof res?.error === 'string') throw new Error(res.error);
        return res;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * @param {*} algorithm 
     * @param {*} key 
     * @param {*} data 
     */
    async sign(algorithm, key, data) {
        const me = this;
        me.#verifyName(algorithm, key);
        const res = key.sign(me.#toUint8Array(data), algorithm);
        if (typeof res?.error === 'string') throw new Error(res.error);
        return me.asRaw ? res.buffer : res;;
    }

    /**
     * Refer to https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
     * @param {*} algorithm 
     * @param {*} key 
     * @param {*} signature 
     * @param {*} data 
     */
    async verify(algorithm, key, signature, data) {
        const me = this;
        me.#verifyName(algorithm, key);
        const res = key.verify(me.#toUint8Array(signature), me.#toUint8Array(data), algorithm);
        if (typeof res?.error === 'string') throw new Error(res.error);
        return res;
    }

    async unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgo, unwrappedKeyAlgo, extractable, keyUsages) {
        throw new Error(CryptoJS.#ERR_UNSUPPORTED);
    }

    async wrapKey(format, key, wrappingKey, wrapAlgo) {
        throw new Error(CryptoJS.#ERR_UNSUPPORTED);
    }

}