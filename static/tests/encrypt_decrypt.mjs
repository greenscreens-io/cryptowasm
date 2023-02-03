import { textBin, buf2hex } from './const.mjs';

const txtHex = buf2hex(textBin);

export default class EncryptDecrypt {

    static filterKey(key) {
        key = key.privateKey || key.publicKey || key;
        return key.usages.indexOf('encrypt') > -1 || key.usages.indexOf('decrypt') > -1;
    }

    static filterKeys(keys) {
        const obj = {};
        Object.entries(keys).filter(kv => EncryptDecrypt.filterKey(kv[1])).forEach(a => obj[a[0]] = a[1]);
        return obj;
    }

    static filter(keys) {
        return {
            wasm: EncryptDecrypt.filterKeys((keys.wasm)),
            native: EncryptDecrypt.filterKeys((keys.native))
        }
    }

    static async encdecSync(key1, key2) {

        const name = key1.algorithm.name || key2.algorithm.name;
        const algorithm = {
            name: name
        };

        const rand = crypto.getRandomValues(new Uint8Array(16));
        switch (name) {
            case 'AES-CTR':
                algorithm.counter = rand;
                algorithm.length = (rand.length * 8) / 2;
                break;
            case 'AES-CBC':
            case 'AES-GCM':
                algorithm.iv = rand;
                break;
        }

        const keyWasm = key1 instanceof CryptoKey ? key2 : key1;
        const keyNative = key1 instanceof CryptoKey ? key1 : key2;
        const binval = await CryptoJS.encrypt(algorithm, keyWasm, textBin);
        const binres = await crypto.subtle.decrypt(algorithm, keyNative, binval);
        const res = buf2hex(binres) == txtHex;
        console.assert(res, algorithm, keyNative.algorithm);
    }

    static async encdecAsyncNative(algorithm, publicKey, privateKey, data) {
        const raw1 = await crypto.subtle.encrypt(algorithm, publicKey, data);
        const binres1 = await CryptoJS.decrypt(algorithm, privateKey, raw1);        
        const res1 = buf2hex(binres1) == buf2hex(data);
        console.assert(res1, algorithm, privateKey.algorithm);
    }

    static async encdecAsyncWasm(algorithm, publicKey, privateKey, data) {
        const raw2 = await CryptoJS.encrypt(algorithm, publicKey, data);
        const binres2 = await crypto.subtle.decrypt(algorithm, privateKey, raw2);
        const res2 = buf2hex(binres2) == buf2hex(data);
        console.assert(res2, algorithm, privateKey.algorithm);
    }

    static async encdecAsync(key1, key2) {

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
        
        const data = textBin.slice(23);
        
        await EncryptDecrypt.encdecAsyncNative(algorithm, nativeKey.publicKey, wasmKey.privateKey, data);
        await EncryptDecrypt.encdecAsyncWasm(algorithm, wasmKey.publicKey, nativeKey.privateKey, data);
    }

    static async encdec(key1, key2) {
        if (key1.publicKey || key1.privateKey) {
            return EncryptDecrypt.encdecAsync(key1, key2);
        }
        return EncryptDecrypt.encdecSync(key1, key2);
    }

    static async testAll(generated, imported) {
        generated = EncryptDecrypt.filter(generated);
        imported = EncryptDecrypt.filter(imported);
        const list1 = Object.keys(generated.native).map(n => EncryptDecrypt.encdec(generated.native[n], imported.wasm[n]));
        const list2 = Object.keys(generated.wasm).map(n => EncryptDecrypt.encdec(generated.wasm[n], imported.native[n]));
        await Promise.all(list1);
        await Promise.all(list2);
    }
} 