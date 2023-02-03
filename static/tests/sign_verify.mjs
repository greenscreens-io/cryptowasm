import { textBin, buf2hex } from './const.mjs';

export default class SignVerify {

    static filterKey(key) {
        key = key.privateKey || key.publicKey || key;
        return key.usages.indexOf('sign') > -1 || key.usages.indexOf('verify') > -1;
    }

    static filterKeys(keys) {
        const obj = {};
        Object.entries(keys).filter(kv => SignVerify.filterKey(kv[1])).forEach(a => obj[a[0]]=a[1]);
        return obj;
    }

    static filter(keys) {
        return {
            wasm : SignVerify.filterKeys((keys.wasm)),
            native : SignVerify.filterKeys((keys.native))
        }
    }

    static async signverSync(key1, key2) {

        const name = key1.algorithm.name || key2.algorithm.name;
        const algorithm = {
            name: name
        };        
        const keyWasm = key1 instanceof CryptoKey ? key2 : key1;
        const keyNative = key1 instanceof CryptoKey ? key1 : key2;
        
        const data = textBin;
        const signature1 = await crypto.subtle.sign(algorithm, keyNative, data);
        const signature2 = await CryptoJS.sign(algorithm, keyWasm, data);
        
        const verify1 = await crypto.subtle.verify(algorithm, keyNative, signature2, data);
        const verify2 = await CryptoJS.verify(algorithm, keyWasm, signature1, data);

        const res1 = buf2hex(signature1) == buf2hex(signature2);
        console.assert(res1, algorithm, keyNative.algorithm);

        console.assert(verify1, algorithm, keyNative.algorithm);
        console.assert(verify2, algorithm, keyWasm.algorithm);
    }

    static async signverAsyncNative(algorithm, privateKey, publicKey, data) {
        const signature = await crypto.subtle.sign(algorithm, privateKey, data);
        const res = await CryptoJS.verify(algorithm, publicKey, signature, data);
        console.assert(res, algorithm, privateKey.algorithm);
    }

    static async signverAsyncWasm(algorithm, privateKey, publicKey, data) {
        const signature = await CryptoJS.sign(algorithm, privateKey, data);
        const res = await crypto.subtle.verify(algorithm, publicKey, signature, data);
        if (!res) debugger;
        console.assert(res, algorithm, privateKey.algorithm);
    }

    static async signverAsync(key1, key2) {
        let nativeKey = null;
        let wasmKey = null;

        if (key1.privateKey instanceof CryptoKey || key1.publicKey instanceof CryptoKey) {
            nativeKey = key1;
            wasmKey = key2;
        } else {
            nativeKey = key2;
            wasmKey = key1;
        }
    
        const name = key1.privateKey.algorithm.name || key1.publicKey.algorithm.name;
        const hash = key1.privateKey.algorithm.hash?.name || key1.publicKey.algorithm.hash?.name || 'SHA-256';
        const algorithm = {
            name: name,
            hash: {name : hash}
        };

        if (name === 'RSA-PSS') {
            // algorithm.saltLength = 0; // not supported by GO lib
            algorithm.saltLength = parseInt(hash.split('-')[1]) || 0;
            algorithm.saltLength = (Math.floor(algorithm.saltLength/8) || 20) -2;
            // algorithm.saltLength = Math.ceil((nativeKey.privateKey.algorithm.modulusLength - 1)/8) - algorithm.saltLength  - 2;
        }

        const data = textBin;
        await SignVerify.signverAsyncNative(algorithm, nativeKey.privateKey, wasmKey.publicKey, data);
        await SignVerify.signverAsyncWasm(algorithm, wasmKey.privateKey, nativeKey.publicKey, data);
    }

    static async signver(key1, key2) {
        if (key1.publicKey || key1.privateKey) {
            return SignVerify.signverAsync(key1, key2);
        } else {
            return SignVerify.signverSync(key1, key2);
        }
    }

    static async testAll(generated, imported) {
        generated = SignVerify.filter(generated);
        imported = SignVerify.filter(imported);
        const list1 = Object.keys(generated.native).map(n => SignVerify.signver(generated.native[n], imported.wasm[n]));
        const list2 = Object.keys(generated.wasm).map(n => SignVerify.signver(generated.wasm[n], imported.native[n]));
        await Promise.all(list1);
        await Promise.all(list2);
    }
}
