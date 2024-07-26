const nacl = require('tweetnacl');
const blake2b = require('blake2b');

class BlinderState {
    constructor(u, v, r, e) {
        this.u = u;
        this.v = v;
        this.r = r;
        this.e = e;
    }

    static new(rp, message) {
        const u = nacl.randomBytes(32);
        const v = nacl.randomBytes(32);

        const rpPoint = nacl.scalarMult.base(rp);
        const r = nacl.scalarMult.base(u);
        nacl.scalarMult.base(v).forEach((byte, i) => r[i] ^= byte);
        rpPoint.forEach((byte, i) => r[i] ^= byte);

        const e = generateE(r, message);
        const ep = generateEp(u, e);

        return {
            ep: ep,
            state: new BlinderState(u, v, r, e)
        };
    }

    genSignedMsg(blindedSignature) {
        const s = new Uint8Array(32);
        nacl.scalarMult(this.u, blindedSignature).forEach((byte, i) => s[i] = byte);
        this.v.forEach((byte, i) => s[i] ^= byte);

        return {
            e: this.e,
            s: s,
            r: this.r
        };
    }
}

function generateE(r, message) {
    const hash = blake2b(64);
    hash.update(r);
    hash.update(message);
    return hash.digest().slice(0, 32);
}

function generateEp(u, e) {
    const uInv = nacl.scalarMult.scalarMultBase(u);
    return nacl.scalarMult(uInv, e);
}

module.exports = BlinderState;
