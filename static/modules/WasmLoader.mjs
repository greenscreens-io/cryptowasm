/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */

/**
 * WASM file loader
 */
export default class WasmLoader {

    static RETURN_RAW = true;
    static #ready = false;
    static #iid = 0;
    static #raw = null;

    static get ready() {
        return WasmLoader.#ready;
    }

    static get GOPATH() {
        const urlLib = globalThis.CRYPTO_GO || '';
        return `${urlLib}/wasm_exec.min.js`
    }

    static get WASMPATH() {
        const urlLib = globalThis.CRYPTO_WASM || '';
        return `${urlLib}/cryptojs.wasm`
    }

    static #release() {
        WasmLoader.#ready = false;
        if (WasmLoader.#iid) clearInterval(WasmLoader.#iid);
        WasmLoader.#iid = 0;
    }

    static async init() {
        if (WasmLoader.#ready) return;
        WasmLoader.#raw = null;
        WasmLoader.#iid = 0;
        const go = await WasmLoader.#initGO();
        const result = await WasmLoader.#loadWasm(WasmLoader.WASMPATH, go.importObject);
        go.run(result.instance).then(() => WasmLoader.#release());
        WasmLoader.#iid = globalThis.CryptoWasm.GCToken()
        WasmLoader.#ready = true;
        WasmLoader.#raw = { result, go };        
    }

    static async #initGO() {
        await import(WasmLoader.GOPATH);
        const go = new globalThis.Go();
        // for tinygo script only - check IMPORTANT.md document
        // if (go.importObject.env) go.importObject.env["syscall/js.finalizeRef"] = () => { };
        return go;
    }

    static async #loadWasm(wasm, imports) {
        if (typeof WebAssembly !== 'object' || typeof WebAssembly.instantiate !== 'function') {
            throw new Error('WebAssembly is not supported.');
        }
        return await WebAssembly.instantiateStreaming(fetch(wasm), imports);
    }

    static #downloadBlob(data, fileName, mimeType) {
        const blob = new Blob([data], { type: mimeType });
        const url = globalThis.URL.createObjectURL(blob);
        WasmLoader.#downloadURL(url, fileName);
        setTimeout(() => globalThis.URL.revokeObjectURL(url), 1000);
    }

    static #downloadURL(data, fileName) {
        const a = document.createElement('a');
        a.href = data;
        a.download = fileName;
        a.click();
    }

    /**
     * For debug purposes; download alocated wasm memory content
    static downloadMemory() {
        if (!WasmLoader.#raw) return;
        const buff = new Uint8Array(WasmLoader.#raw.result.instance.exports.mem.buffer);
        WasmLoader.#downloadBlob(buff, 'wasm.memory.bin', 'application/octet-stream');
    }
    */
}