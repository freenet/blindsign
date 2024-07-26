import nacl from 'tweetnacl';
import blake2b from 'blake2b';

export class BlinderState {
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
        const s = nacl.scalarMult(blindedSignature, this.u);
        for (let i = 0; i < 32; i++) {
            s[i] ^= this.v[i];
        }

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
    const uInv = nacl.scalarMult.base(u);
    return nacl.scalarMult(e, uInv);
}
