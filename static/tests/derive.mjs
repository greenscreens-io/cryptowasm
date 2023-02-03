import { buf2hex } from './const.mjs';

export default class DeriveKey {

    static filterKey(key, isAsync) {
        if (isAsync && !(key.privateKey || key.publicKey)) return false;
        key = key.privateKey || key.publicKey || key;
        return key.usages.indexOf('deriveKey') > -1 || key.usages.indexOf('deriveBits') > -1;
    }

    static filterKeys(keys, isAsync) {
        const obj = {};
        Object.entries(keys).filter(kv => DeriveKey.filterKey(kv[1], isAsync)).forEach(a => obj[a[0]]=a[1]);
        return obj;
    }

    static filter(keys, isAsync) {
        return {
            wasm : DeriveKey.filterKeys(keys.wasm, isAsync),
            native : DeriveKey.filterKeys(keys.native, isAsync)
        }
    }

    static async deriveSync(key1, key2) {

        const name = key1.algorithm.name || key2.algorithm.name;
        const hash = key1.algorithm.hash?.name || key1.algorithm.hash?.name || 'SHA-256';
        const size = (parseInt(hash.split('-')[1]) / 8) || 20;

        const algorithm = {
            name: name,
            hash : hash,
            salt : crypto.getRandomValues(new Uint8Array(size)),
            iterations : 1000,
            info : new Uint8Array()
        };        

        const keyWasm = key1 instanceof CryptoKey ? key2 : key1;
        const keyNative = key1 instanceof CryptoKey ? key1 : key2;
        
        const rn = await window.crypto.subtle.deriveBits(algorithm, keyNative, 128);
        const rw = await CryptoJS.deriveBits(algorithm, keyWasm, 128);

        const nh = buf2hex(rn);
        const wh = buf2hex(rw);
        console.assert(nh == wh, nh, wh, algorithm, keyNative.algorithm, keyWasm.algorithm);
    }

    static async deriveAsyncNative(algorithm, privateKey, publicKey) {
    }

    static async deriveAsyncWasm(algorithm, privateKey, publicKey) {
    }

    static async deriveAsync(key1, key2) {

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
        const algorithm = {
            name: name
        };

        await DeriveKey.deriveAsyncNative(algorithm, nativeKey.privateKey, wasmKey.publicKey);
        await DeriveKey.deriveAsyncWasm(algorithm, wasmKey.privateKey, nativeKey.publicKey);        
    }

    static async derive(key1, key2) {
        if (key1.publicKey || key1.privateKey) {
            return DeriveKey.deriveAsync(key1, key2);
        } else if (key1 && key2) {
            return DeriveKey.deriveSync(key1, key2);
        }
    }

    static async testAll(generated, imported) {
        generated = DeriveKey.filter(generated, true);
        imported = DeriveKey.filter(imported, false);
        const list1 = Object.keys(generated.native).map(n => DeriveKey.derive(generated.native[n], imported.wasm[n]));
        const list2 = Object.keys(generated.wasm).map(n => DeriveKey.derive(generated.wasm[n], imported.native[n]));
        const list3 = Object.keys(imported.wasm).map(n => DeriveKey.derive(imported.wasm[n], imported.native[n]));
        await Promise.all(list1);
        await Promise.all(list2);
        await Promise.all(list3);
    }
}
