/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
import CryptoJSWasm from './lib/WasmLoader.mjs'
import CryptoJS from './lib/CryptoJS.mjs'

globalThis.CRYPTO_WASM = '/lib';
globalThis.CRYPTO_GO = '/lib';
await CryptoJSWasm.init();

globalThis.CryptoJS = new CryptoJS();

import {testAll} from './tests/index.mjs';

await testAll();