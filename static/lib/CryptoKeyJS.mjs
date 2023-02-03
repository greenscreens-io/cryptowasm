/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
export default class CryptoKeyJS {

    static #ERR_INVALID_SHA = 'Invalid SHA-x';
    static #ERR_INVALID_ALG = 'Invalid algorithm';

    static #ASYNC_KEYS = ['ECDSA', 'ECDH', 'RSA-PSS', 'RSA-OAEP', 'RSASSA-PKCS1-v1_5', 'Ed25519', 'X25519'];
    static #PRIVATE_OPS = ['sign', 'decrypt', 'deriveBits', 'deriveKey'];

    #algorithm;
    #extractable;
    #usages;
    #key;

    constructor(algorithm, extractable, usages, key) {

        if (typeof key?.error === 'string') throw new Error(key.error);

        if (extractable && (algorithm.name || algorithm).indexOf('KDF') > -1) {
            throw new DOMException("KDF keys must set extractable=false");
        }

        const me = this;
        me.#algorithm = algorithm;
        me.#extractable = extractable;
        me.#usages = usages;
        me.#key = key;
    }

    get extractable() {
        return this.#extractable;
    }

    get isAsync() {
        return CryptoKeyJS.#ASYNC_KEYS.indexOf(this.#algorithmName) > -1;
    }

    get isPublic() {
        const me = this;
        if (!me.isAsync) return false;
        return me.#usages.length === 0 || ['verify', 'encrypt'].some(r => me.#usages.includes(r));
    }

    get isPrivate() {
        const me = this;
        if (!me.isAsync) return false;
        return CryptoKeyJS.#PRIVATE_OPS.some(r => me.#usages.includes(r));
    }

    get type() {
        const me = this;
        if (!me.isAsync) return 'secret';
        return me.isPrivate ? 'private' : 'public';
    }

    get algorithm() {
        if (typeof this.#algorithm === 'string') return this.#algorithm;
        return Object.assign({}, this.#algorithm);
    }

    get usages() {
        return Array.from(this.#usages);
    }

    get crypto() {
        globalThis.CryptoWasm.gc = true;
        return globalThis.CryptoWasm;
    }

    get #hashName() {
        const algo = this.#algorithm;
        return algo.hash?.name || algo.hash || algo.namedCurve;
    }

    get #algorithmName() {
        return this.#algorithm.name || this.#algorithm;
    }

    get #hashSize() {
        return CryptoKeyJS.hashSize(this.#hashName);
    }

    get #hashid() {
        return this.#hashID(this.#hashName);
    }

    get #jwkAlgo() {

        const me = this;
        const hbit = me.#hashid;

        if (me.isAsync) {
            switch(me.#algorithmName) {
                case 'RSASSA-PKCS1-v1' : return `RS${hbit}`;
                case 'RSA-OAEP' : return  hbit === 1 ? 'RSA-OAEP' : `RSA-OAEP-${hbit}`;
                case 'RSA-PSS' : return `PS${hbit}`;
            }
            return null;
        }

        if (me.#algorithmName === 'HMAC') {
            return `HS${me.#algorithm.length || me.#hashid}`;
        } 

        return `A${me.#algorithm.length}${me.#algorithmName.split('-')[1]}`;
    }

    #hashID(hash = '') {
        return parseInt(hash.split('-')[1]);
    }

    #verify(format, expected) {
        if (!this.#extractable) throw new DOMException('InvalidAccessError');
        if (expected.indexOf(format) < 0) throw new DOMException('NotSupported');
    }

    #verifyAsync(format) {
        return this.#verify(format, ['pkcs8', 'spki', 'jwk']);
    }

    #exportLocal(format) {
        const me = this;
        me.#verify(format, ['raw', 'jwk']);
        if (format === 'raw') return me.#key;
        return {
            "alg" : me.#jwkAlgo,
            "ext" : true,
            "k" : me.crypto.toB64(me.#key, true),
            "key_ops" : me.#usages,
            "kty" : "oct"
        }
    }

    #exportKeyAsync(format, obj) {
        
        const me = this;
        me.#verifyAsync(format);
        const fmt = format === 'jwk' ? 2 : 0;
        const key = obj.ExportKey(me.#key, me.isPublic, fmt);
        if (format === 'raw') return key;

        key.key_ops = me.#usages;
        
        const isRSA = me.#algorithmName.indexOf('RSA') === 0;
        if (isRSA) key.alg = me.#jwkAlgo;
        // if (!isRSA) key.crv = me.#algorithm.namedCurve;

        return key;
    }

    #signHMAC(data) {
        const me = this;
        const hmac = me.crypto.hmac;
        const name = me.#hashName
        switch (name) {
            case 'SHA-1': return hmac.Hmac1Sign(data, me.#key);
            case 'SHA-256': return hmac.Hmac256Sign(data, me.#key);
            case 'SHA-384': return hmac.Hmac384Sign(data, me.#key);
            case 'SHA-512': return hmac.Hmac512Sign(data, me.#key);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_SHA} : ${name}`);
        }

    }

    #verifyHMAC(signature, data) {
        const me = this;
        const hmac = me.crypto.hmac;
        const name = me.#hashName
        switch (name) {
            case 'SHA-1': return hmac.Hmac1Verify(data, signature, me.#key);
            case 'SHA-256': return hmac.Hmac256Verify(data, signature, me.#key);
            case 'SHA-384': return hmac.Hmac384Verify(data, signature, me.#key);
            case 'SHA-512': return hmac.Hmac512Verify(data, signature, me.#key);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_SHA} : ${name}`);
        }

    }

    #signRSASA(data) {
        const me = this;
        return me.crypto.rsa.SignPKCS1v15(me.#key, data, me.#hashSize);
    }

    #verifyRSASA(signature, data) {
        const me = this;
        return me.crypto.rsa.VerifyPKCS1v15(me.#key, data, signature, me.#hashSize);
    }

    #signPSS(data, opt) {
        const me = this;
        const saltLength = opt.saltLength || 0;
        return me.crypto.rsa.SignPSS(me.#key, data, me.#hashSize, saltLength);
    }

    #verifyPSS(signature, data, opt) {
        const me = this;
        const saltLength = opt.saltLength || 0;
        return me.crypto.rsa.VerifyPSS(me.#key, data, signature, me.#hashSize, saltLength);
    }

    #signEcdsa(data, opt) {
        const me = this;
        if (me.#algorithm.namedCurve === 'Ed25519') {
            return me.#signEd25519(data);
        }
        const hash = opt.hash.name || opt.hash;
        const size = me.#hashID(hash);
        return me.crypto.ecdsa.Sign(me.#key, data, size, false);
    }

    #verifyEcdsa(signature, data, opt) {
        const me = this;
        if (me.#algorithm.namedCurve === 'Ed25519') {
            return me.#verifyEd25519(signature, data);
        }
        const hash = opt.hash.name || opt.hash;
        const size = me.#hashID(hash);
        return me.crypto.ecdsa.Verify(me.#key, data, signature, size, false);
    }

    #signEd25519(data) {
        const me = this;
        return me.crypto.ed25519.Sign(me.#key, data, false);
    }

    #verifyEd25519(signature, data) {
        const me = this;
        return me.crypto.ed25519.Verify(me.#key, data, signature, false);
    }

    #deriveECDHBits(algorithm, bitLength = 0) {
        const me = this;
        const keylen = CryptoKeyJS.curveSize(me.#algorithm.namedCurve);
        if (bitLength > keylen || (keylen === 25519 && bitLength > 256)) throw new DOMException('OperationError');
        if (bitLength === 0) return new Uint8Array();
        const raw = me.crypto.ecdh.DeriveKey(me.#key, algorithm.public.#key, bitLength);
        if (typeof raw?.error === 'string') throw new Error(raw.error);
        return raw;
    }

    #deriveHKDFBits(algorithm, bitLength) {
        if (!bitLength || bitLength === 0 || bitLength % 8 > 0) throw new DOMException('OperationError');
        const me = this;
        return me.crypto.GenerateHKDF(me.#key, algorithm.salt, algorithm.info, bitLength);
    }

    #derivePBKDF2Bits(algorithm, bitLength) {
        if (bitLength === 0) return new Uint8Array();
        const me = this;
        const size = CryptoKeyJS.hashSize(algorithm.hash);
        return me.crypto.GeneratePBKDF2(me.#key, algorithm.salt, algorithm.iterations, bitLength, size);
    }

    #deriveECDHKey(algorithm, derivedKeyAlgorithm, extractable, keyUsages) {
        let length = 0;
        const key = this.#deriveECDHBits(algorithm, length);
        return new CryptoKeyJS(derivedKeyAlgorithm, extractable, keyUsages, key);
    }

    #deriveHKDFKey(algorithm, derivedKeyAlgorithm, extractable, keyUsages) {
        const size = CryptoKeyJS.hashSize(algorithm.hash);
        const key = this.#deriveHKDFBits(algorithm, size);
        return new CryptoKeyJS(derivedKeyAlgorithm, extractable, keyUsages, key);
    }

    #derivePBKDF2Key(algorithm, derivedKeyAlgorithm, extractable, keyUsages) {
        const me = this;
        const len = derivedKeyAlgorithm.length || CryptoKeyJS.hashSize(derivedKeyAlgorithm.hash);
        const key = me.#derivePBKDF2Bits(algorithm, len);
        return new CryptoKeyJS(derivedKeyAlgorithm, extractable, keyUsages, key);
    }

    deriveBits(algorithm, length) {

        const me = this;
        const keyName = me.#algorithmName;
        const name = algorithm.name === keyName ? algorithm.name : `${algorithm.name} <-> ${keyName}`;

        switch (name) {
            case 'X25519':
            case 'ECDH': return me.#deriveECDHBits(algorithm, length);
            case 'HKDF': return me.#deriveHKDFBits(algorithm, length);
            case 'PBKDF2': return me.#derivePBKDF2Bits(algorithm, length);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_ALG} : ${name}`);
        }
    }

    deriveKey(algorithm, derivedKeyAlgorithm, extractable, keyUsages) {

        const me = this;
        const keyName = me.#algorithmName;
        const name = algorithm.name === keyName ? algorithm.name : `${algorithm.name} <-> ${keyName}`;

        switch (name) {
            case 'X25519':
            case 'ECDH': return me.#deriveECDHKey(algorithm, derivedKeyAlgorithm, extractable, keyUsages);
            case 'HKDF': return me.#deriveHKDFKey(algorithm, derivedKeyAlgorithm, extractable, keyUsages);
            case 'PBKDF2': return me.#derivePBKDF2Key(algorithm, derivedKeyAlgorithm, extractable, keyUsages);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_ALG} : ${name}`);
        }

    }

    sign(data, opt) {
        const me = this;
        const name = me.#algorithmName;
        switch (name) {
            case 'RSASSA-PKCS1-v1_5': return me.#signRSASA(data);
            case 'RSA-PSS': return me.#signPSS(data, opt);
            case 'ECDSA': return me.#signEcdsa(data, opt);
            case 'HMAC': return me.#signHMAC(data);
            case 'Ed25519': return me.#signEd25519(data);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_ALG} : ${name}`);
        }
    }

    verify(signature, data, opt) {
        const me = this;
        const name = me.#algorithmName;
        switch (name) {
            case 'RSASSA-PKCS1-v1_5': return me.#verifyRSASA(signature, data);
            case 'RSA-PSS': return me.#verifyPSS(signature, data, opt);
            case 'ECDSA': return me.#verifyEcdsa(signature, data, opt);
            case 'HMAC': return me.#verifyHMAC(signature, data);
            case 'Ed25519': return me.#verifyEd25519(signature, data);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_ALG} : ${name}`);
        }
    }

    decrypt(data, iv) {
        const me = this;
        const aes = me.crypto.aes;
        const name = me.#algorithmName;
        switch (name) {
            case 'RSA-OAEP': return me.crypto.rsa.Decrypt(me.#key, me.#hashSize, data);
            case 'AES-CTR': return aes.CTRDecrypt(me.#key, data, iv);
            case 'AES-CBC': return aes.CBCDecrypt(me.#key, data, iv);
            case 'AES-GCM': return aes.GCMDecrypt(me.#key, data, iv);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_ALG} : ${name}`);
        }
    }

    encrypt(data, iv) {
        const me = this;
        const aes = me.crypto.aes;
        const name = me.#algorithmName;
        switch (name) {
            case 'RSA-OAEP': return me.crypto.rsa.Encrypt(me.#key, me.#hashSize, data);
            case 'AES-CTR': return aes.CTREncrypt(me.#key, data, iv);
            case 'AES-CBC': return aes.CBCEncrypt(me.#key, data, iv);
            case 'AES-GCM': return aes.GCMEncrypt(me.#key, data, iv);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_ALG} : ${name}`);
        }
    }

    export(format) {
        const me = this;
        if (!me.#extractable) throw new DOMException('InvalidAccessError');
        const name = me.#algorithmName;
        switch (name) {
            case 'AES-CBC':
            case 'AES-CTR':
            case 'AES-GCM':
            case 'HMAC':
            case 'PBKDF2':
            case 'HKDF':
                return me.#exportLocal(format);
            case 'RSASSA-PKCS1-v1_5':
            case 'RSA-OAEP':
            case 'RSA-PSS':
                return me.#exportKeyAsync(format, me.crypto.rsa);
            case 'ECDSA':
                return me.#exportKeyAsync(format, me.crypto.ecdsa);
            case 'ECDH':
                return me.#exportKeyAsync(format, me.crypto.ecdh);
            case 'Ed25519':
                return me.#exportKeyAsync(format, me.crypto.ed25519);
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_ALG} : ${name}`);
        }

    }

    static curveSize(curve) {
        switch (curve) {
            case 'P-256':
                return 256;
            case 'P-384':
                return 384;
            case 'P-521':
                return 521;
            case 'Ed25519':
            case 'X25519':
                return 25519;
            default: throw new Error('Invalid Curve');
        }
    }

    static blockSize(hash) {
        let size = 0;
        switch (hash) {
            case 'SHA-1':
            case 'SHA-256':
                size = 512;
                break;
            case 'SHA-384':
            case 'SHA-512':
                size = 1024;
                break;
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_SHA} : ${hash}`);
        }
        return size;
    }

    static hashSize(hash) {
        let size = 0;
        switch (hash) {
            case 'SHA-1':
                size = 20;
                break;
            case 'SHA-256':
                size = 32;
                break;
            case 'SHA-384':
                size = 48;
                break;
            case 'SHA-512':
                size = 64;
                break;
            default: throw new Error(`${CryptoKeyJS.#ERR_INVALID_SHA} : ${hash}`);
        }
        return size;
    }
}
