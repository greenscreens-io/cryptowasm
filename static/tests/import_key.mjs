import { cartesian } from './const.mjs';

export default class ImportKey {

    static isFormatKey(format, key) {
        const isAsync = key.publicKey || key.privatekey;
        return (format === 'raw' && !isAsync) || (format !== 'raw' && isAsync);
    }

    static formatKey(format, key) {
        switch (format) {
            case 'raw': return key;
            case 'spki': return key.publicKey;
            case 'pkcs8': return key.privateKey;
        }
    }

    static formatUsages(format, key) {
        if (format === 'spki' && key.algorithm.name === 'ECDH') return [];
        return key.usages;
    }

    static async importNative(format, key, name, result) {
        key = ImportKey.formatKey(format, key);
        const usages = ImportKey.formatUsages(format, key);
        let newkey = null;
        
        try {
            newkey = await crypto.subtle.importKey(format, key.raw, key.algorithm, true, usages);
        } catch(e) {
            console.error('native not imported: ', name, format, key.algorithm, usages);
            return;
        }

        if (!result[name]) result[name] = {};

        switch (format) {
            case 'raw':
                result[name] = newkey;
                break;
            case 'spki':
                result[name]['publicKey'] = newkey;
                break;
            case 'pkcs8':
                result[name]['privateKey'] = newkey;
                break;

        }
    }

    static async importWasm(format, key, name, result) {
        key = ImportKey.formatKey(format, key);
        const usages = ImportKey.formatUsages(format, key);

        let newkey = null;
        
        try {
            newkey = await CryptoJS.importKey(format, key.raw, key.algorithm, true, usages);
        } catch(e) {
            console.error('wasm not imported: ', name, format, key.algorithm, usages);
            return;
        }

        if (!result[name]) result[name] = {};

        switch (format) {
            case 'raw':
                result[name] = newkey;
                break;            
            case 'spki':
                result[name]['publicKey'] = newkey;
                break;
            case 'pkcs8':
                result[name]['privateKey'] = newkey;
                break;

        }
    }

    static async derive(result) {
        const data = new TextEncoder().encode('quick fox jumps over lazy dog');
        result.native.HKDF = await window.crypto.subtle.importKey('raw', data, 'HKDF', false, ['deriveKey','deriveBits'])
        result.native.PBKDF2 = await window.crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveKey','deriveBits'])        
        result.wasm.HKDF = await CryptoJS.importKey('raw', data, 'HKDF', false, ['deriveKey','deriveBits'])
        result.wasm.PBKDF2 = await CryptoJS.importKey('raw', data, 'PBKDF2', false, ['deriveKey','deriveBits'])        
    }

    static async testAll(data) {
        const result = {
            native: {},
            wasm: {}
        };
        const formats = ['raw', 'pkcs8', 'spki'];
        const nativeMap = cartesian(Object.entries(data.native), formats).filter(a => ImportKey.isFormatKey(a[2], a[1]));
        const wasmMap = cartesian(Object.entries(data.wasm), formats).filter(a => ImportKey.isFormatKey(a[2], a[1]));
        const nativeList = wasmMap.map(a => ImportKey.importNative(a[2], a[1], a[0], result.native));
        const wasmList = nativeMap.map(a => ImportKey.importWasm(a[2], a[1], a[0], result.wasm));
        await Promise.all(nativeList);
        await Promise.all(wasmList);
        await ImportKey.derive(result);
        return result;
    }
} 