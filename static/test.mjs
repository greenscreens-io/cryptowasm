/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
import CryptoJSWasm from './modules/WasmLoader.mjs'
import CryptoJS from './modules/CryptoJS.mjs'

globalThis.CRYPTO_WASM = '/release';
globalThis.CRYPTO_GO = '/release';

await CryptoJSWasm.init();

globalThis.CryptoJS = new CryptoJS();

import {testAll} from './tests/index.mjs';

await testAll();