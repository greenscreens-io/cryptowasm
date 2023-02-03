import {cartesian, keyUsagesMap} from './const.mjs';

export default class GenerateKey {

    static async generateKey(algorithm, result) {
        result.native[algorithm.id] = await crypto.subtle.generateKey(algorithm, true, keyUsagesMap[algorithm.name]);
        result.wasm[algorithm.id] = await CryptoJS.generateKey(algorithm, true, keyUsagesMap[algorithm.name]);
        console.log(`Generate: ${algorithm.id}`);
    }

    static rsaCartesian() {
        const names = ['RSA-PSS', 'RSA-OAEP', 'RSASSA-PKCS1-v1_5'];
        const modulus = [1024]; // 2048, 4096 takes too long in wasm 
        const hash = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
        return cartesian(names, modulus, hash);
    }
    
    static rsaParmToObj(name, modulusLength, hash, publicExponent) {
        const id = `${name}_${hash}_${modulusLength}`;
        return {name, modulusLength, hash, publicExponent, id}
    }

    static rsaParams() {
        const publicExponent = new Uint8Array([0x01, 0x00, 0x01]);
        return GenerateKey.rsaCartesian()
            // https://crypto.stackexchange.com/questions/42097/what-is-the-maximum-size-of-the-plaintext-message-for-rsa-oaep
            .filter(a => !(a[0] === 'RSA-OAEP' && a[1] === 1024 && a[2] === 'SHA-512'))
            .map(a => GenerateKey.rsaParmToObj(a[0],a[1],a[2],publicExponent));
    }

    static ecCartesian() {
        const names = ['ECDSA', 'ECDH'];
        const hash = ['P-256', 'P-384', 'P-521'];
        return cartesian(names, hash);
    }

    static ecParmToObj(name, namedCurve) {
        const id = `${name}_${namedCurve}`;
        return {name, namedCurve, id}
    }

    static ecParams() {
        return GenerateKey.ecCartesian().map(a => GenerateKey.ecParmToObj(a[0],a[1]));
    }

    static hmacCartesian() {
        const names = ['HMAC'];
        const hash = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
        return cartesian(names, hash);
    }

    static hmacParmToObj(name, hash) {
        const id = `${name}_${hash}`;
        return {name, hash, id}
    }

    static hmacParams() {
        return GenerateKey.hmacCartesian().map(a => GenerateKey.hmacParmToObj(a[0],a[1]));
    }

    static aesCartesian() {
        const names = ['AES-CBC', 'AES-CTR', 'AES-GCM']; // AES-KW not supported
        const lengths = [128, 256];
        return cartesian(names, lengths);
    }

    static aesParmToObj(name, length) {
        const id = `${name}_${length}`;
        return {name, length, id}
    }

    static aesParams() {
        return GenerateKey.aesCartesian().map(a => GenerateKey.aesParmToObj(a[0],a[1]));
    }

    static async aes(result) {
        const params = GenerateKey.aesParams();        
        await Promise.all(params.map(o => GenerateKey.generateKey(o, result)));
        return result;
    }

    static async hmac(result) {
        const params = GenerateKey.hmacParams();        
        await Promise.all(params.map(o => GenerateKey.generateKey(o, result)));
        return result;
    }

    static async ec(result) {
        const params = GenerateKey.ecParams();        
        await Promise.all(params.map(o => GenerateKey.generateKey(o, result)));
        return result;
    }

    static async rsa(result) {
        const params = GenerateKey.rsaParams();        
        await Promise.all(params.map(o => GenerateKey.generateKey(o, result)));
        return result;
    }

    static async testAll() {
        const result = {
            native : {},
            wasm : {}
        };        
        await GenerateKey.rsa(result);
        await GenerateKey.ec(result);
        await GenerateKey.hmac(result);
        await GenerateKey.aes(result);
        return result;
    }
}