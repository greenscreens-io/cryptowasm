/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
if (!globalThis.crypto.subtle) {
    const { CryptoKeyJS, CryptoJS, WasmLoader } = await import('./release/io.greenscreens.cryptojs.min.js');
    await WasmLoader.init();
    globalThis.crypto.CryptoKeyJS = CryptoKeyJS;
    globalThis.crypto.subtle = new CryptoJS();
    Object.seal(globalThis.crypto.subtle);
    Object.seal(globalThis.crypto);
}
