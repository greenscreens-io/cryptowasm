/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
import WasmLoader from './modules/WasmLoader.mjs'
import CryptoJS from './modules/CryptoJS.mjs'

globalThis.CRYPTO_WASM = '/release';
globalThis.CRYPTO_GO = '/release';
await WasmLoader.init();

globalThis.CryptoJS = new CryptoJS();
