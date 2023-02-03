
const engine = crypto.subtle;
const text = "The quick brown fox jumps over the lazy dog";
const textBin = new TextEncoder().encode(text);

const encdec = ['encrypt', 'decrypt'];
const signver = ['sign', 'verify'];
const derive = ['deriveKey', 'deriveBits'];
const wrap = ['wrapKey', 'unwrapKey'];

const keyUsagesMap = {
    'RSASSA-PKCS1-v1_5' : signver, 
    'RSA-PSS' : signver,
    'ECDSA': signver,
    'HMAC' : signver,
    'RSA-OAEP' : encdec, // wrap unsupported
    'AES-CTR' :  encdec, // wrap unsupported
    'AES-CBC' :  encdec, // wrap unsupported
    'AES-GCM' :  encdec, // wrap unsupported
    'ECDH' : derive,
    'HKDF' : derive,
    'PBKDF2' : derive,
    // 'AES-KW' : wrap //  unsupported
};

const buf2hex = (buffer) => {
    const raw = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
    return Array.from(raw).map(x => x.toString(16).padStart(2, '0')).join('');
}

const cartesian = (...a) => a.reduce((a, b) => a.flatMap(d => b.map(e => [d, e].flat())));

export { engine, text, textBin, keyUsagesMap, buf2hex, cartesian }