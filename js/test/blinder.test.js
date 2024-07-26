import { BlinderState } from '../blinder.js';
import nacl from 'tweetnacl';

describe('BlinderState', () => {
    test('new() creates a valid BlinderState', () => {
        const rp = nacl.randomBytes(32);
        const message = Buffer.from('Test message');
        const { ep, state } = BlinderState.new(rp, message);

        expect(ep).toBeInstanceOf(Uint8Array);
        expect(ep.length).toBe(32);
        expect(state).toBeInstanceOf(BlinderState);
    });

    test('genSignedMsg() generates a valid signed message', () => {
        const rp = nacl.randomBytes(32);
        const message = Buffer.from('Test message');
        const { state } = BlinderState.new(rp, message);
        const blindedSignature = nacl.randomBytes(32);

        const signedMsg = state.genSignedMsg(blindedSignature);

        expect(signedMsg.e).toBeInstanceOf(Uint8Array);
        expect(signedMsg.e.length).toBe(32);
        expect(signedMsg.s).toBeInstanceOf(Uint8Array);
        expect(signedMsg.s.length).toBe(32);
        expect(signedMsg.r).toBeInstanceOf(Uint8Array);
        expect(signedMsg.r.length).toBe(32);
    });
});
