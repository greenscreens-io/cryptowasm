export default class MLKEM {

    static #toBytes(value) {
        return value instanceof ArrayBuffer ? new Uint8Array(value) : value;
    }

    static #equal(left, right) {
        const a = MLKEM.#toBytes(left);
        const b = MLKEM.#toBytes(right);
        return a.length === b.length && a.every((value, index) => value === b[index]);
    }

    static async #roundTrip(algorithm, publicKey, privateKey) {
        const encapsulated = await CryptoJS.encapsulateBits(algorithm, publicKey);
        const sharedKey = await CryptoJS.decapsulateBits(algorithm, privateKey, encapsulated.ciphertext);
        if (!MLKEM.#equal(encapsulated.sharedKey, sharedKey)) {
            throw new Error(`${algorithm.name} encapsulation round trip failed`);
        }
    }

    static async test() {
        for (const name of ['ML-KEM-768', 'ML-KEM-1024']) {
            const algorithm = {name};
            const keys = await CryptoJS.generateKey(algorithm, true, ['encapsulateBits', 'decapsulateBits']);
            await MLKEM.#roundTrip(algorithm, keys.publicKey, keys.privateKey);

            const publicJWK = await CryptoJS.exportKey('jwk', keys.publicKey);
            const privateJWK = await CryptoJS.exportKey('jwk', keys.privateKey);
            const jwkPublic = await CryptoJS.importKey('jwk', publicJWK, algorithm, true, ['encapsulateBits']);
            const jwkPrivate = await CryptoJS.importKey('jwk', privateJWK, algorithm, true, ['decapsulateBits']);
            await MLKEM.#roundTrip(algorithm, jwkPublic, jwkPrivate);

            const publicPEM = await CryptoJS.exportKey('spki', keys.publicKey);
            const privatePEM = await CryptoJS.exportKey('pkcs8', keys.privateKey);
            const pemPublic = await CryptoJS.importKey('spki', publicPEM, algorithm, true, ['encapsulateBits']);
            const pemPrivate = await CryptoJS.importKey('pkcs8', privatePEM, algorithm, true, ['decapsulateBits']);
            await MLKEM.#roundTrip(algorithm, pemPublic, pemPrivate);

            const publicRaw = await CryptoJS.exportKey('raw', keys.publicKey);
            const rawPublic = await CryptoJS.importKey('raw', publicRaw, algorithm, true, ['encapsulateBits']);
            await MLKEM.#roundTrip(algorithm, rawPublic, keys.privateKey);
        }
    }
}
