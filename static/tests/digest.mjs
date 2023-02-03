import {textBin, buf2hex} from './const.mjs';

export default class Digest {

    static assert(v1,v2, title) {
        v1 = buf2hex(v1)
        v2 = buf2hex(v2)
        console.assert(v1 === v2, title, v1, v2)
    }

    static async digestSHA(algo, data) {
        const rn = await crypto.subtle.digest(algo, data);
        const rw = await CryptoJS.digest(algo, data);
        Digest.assert(rn, rw, `Digest.${algo.replace('-','').toLowerCase()}`);
    }

    static digestAll(data) {
        return Promise.all([
            Digest.digestSHA('SHA-1', data),
            Digest.digestSHA('SHA-256', data),
            Digest.digestSHA('SHA-384', data),
            Digest.digestSHA('SHA-512', data)
        ]);
    }

    static test() {
        return this.digestAll(textBin);
    }
}