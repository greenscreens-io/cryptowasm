import GenerateKey from './generate_key.mjs';
import ImportKey from './import_key.mjs';
import ExportKey from './export_key.mjs';
import Digest from './digest.mjs';

import DeriveKey from './derive.mjs';
import EncryptDecrypt from './encrypt_decrypt.mjs';
import SignVerify from './sign_verify.mjs';


function downloadJWK(obj, type) {
    const jwks = {};
    Object.entries(obj).forEach(kv => jwks[kv[0]]= kv[1].jwk);
    const str = JSON.stringify(jwks);

    const blob = new Blob([str], {type: "octet/stream"});
    const url  = window.URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `jwk_${type}.json`;
    a.click();

    window.URL.revokeObjectURL(url);
}

async function testAll() {

    await Digest.test();
    const result = await GenerateKey.testAll();    
    const exported = await ExportKey.testAll(result);        
    const imported = await ImportKey.testAll(exported);
    
    await ExportKey.testAll(imported);    
    downloadJWK(exported.native, 'native');
    downloadJWK(imported.wasm, 'wasm');

    await EncryptDecrypt.testAll(result, imported);
    await SignVerify.testAll(result, imported);
    await DeriveKey.testAll(result, imported);

}

export {testAll}