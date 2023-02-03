import {cartesian} from './const.mjs';

export default class ExportKey {

    static isAsync(key) {
        return key.publicKey || key.privatekey;
    }

    static isFormatKey(format, key) {
        if (format === 'jwk') return true;
        const isAsync = this.isAsync(key);
        return (format === 'raw' && !isAsync) || (format !== 'raw' && isAsync); 
    }

    static formatKey(format, key) {
        switch (format) {
            case 'jwk' : 
            case 'raw' : 
                return key;
            case 'spki' : return key.publicKey;
            case 'pkcs8' : return key.privateKey;
        }
    }

    static async exportJWK(format, key, engine) {
        const isAsync = this.isAsync(key);
        const fn = CryptoWasm.toB64;
        if (isAsync) {
            const privateKey = await engine.exportKey(format, key.privateKey);
            const publicKey = await engine.exportKey(format, key.publicKey);
            if (key.privateKey.raw) privateKey.raw = fn(new Uint8Array(key.privateKey.raw), true);
            if (key.publicKey.raw) publicKey.raw = fn(new Uint8Array(key.publicKey.raw), true);

            key.jwk = {
                privateKey : privateKey,
                publicKey : publicKey
            };  
        } else if(key.extractable) {
            key.jwk = await engine.exportKey(format, key);
        }
    }

    static async exportNative(format, key) {
        if (format === 'jwk') return this.exportJWK(format, key, crypto.subtle);
        key = ExportKey.formatKey(format, key);
        if (!key.extractable) return;
        key.raw = await crypto.subtle.exportKey(format, key);
    }

    static async exportWasm(format, key) {
        try {
            if (format === 'jwk') return this.exportJWK(format, key, CryptoJS);
            key = ExportKey.formatKey(format, key);
            if (!key.extractable) return;
            key.raw = await CryptoJS.exportKey(format, key);
        } catch (e) {
            console.log(`Export key for format : ${format} => ${key}`);
            console.log(e);
        }
    }

    static async testAll(data) {
        const formats = ['raw', 'pkcs8', 'spki', 'jwk'];
        const nativeMap = cartesian(Object.entries(data.native), formats).filter(a => ExportKey.isFormatKey(a[2], a[1]));
        const wasmMap = cartesian(Object.entries(data.wasm), formats).filter(a => ExportKey.isFormatKey(a[2], a[1]));
        const nativeList = nativeMap.map(a => ExportKey.exportNative(a[2], a[1]));
        const wasmList = wasmMap.map(a => ExportKey.exportWasm(a[2], a[1]));
        await Promise.all(nativeList);
        await Promise.all(wasmList);
        return data; 
    }
} 