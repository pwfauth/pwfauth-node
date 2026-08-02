import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { CryptoEnvelope, PwfCryptoError } from '../src/index.js';

const SECRET = 'a'.repeat(64);

test('round-trips a payload', () => {
    const env = new CryptoEnvelope(SECRET);
    const plain = JSON.stringify({ license_key: 'AAAAA-BBBBB', hwid: 'H1' });
    assert.equal(env.decrypt(env.encrypt(plain)), plain);
});

test('produces the {p,t,s} wire shape', () => {
    const o = JSON.parse(new CryptoEnvelope(SECRET).encrypt('{}'));
    assert.deepEqual(Object.keys(o).sort(), ['p', 's', 't']);
    assert.equal(typeof o.t, 'number');
    assert.match(o.s, /^[0-9a-f]{64}$/);
    // p is base64 of IV(16) || ciphertext — at least two AES blocks.
    assert.ok(Buffer.from(o.p, 'base64').length >= 32);
});

test('a fresh IV is used every time', () => {
    const env = new CryptoEnvelope(SECRET);
    assert.notEqual(JSON.parse(env.encrypt('{"a":1}')).p, JSON.parse(env.encrypt('{"a":1}')).p);
});

test('rejects a payload signed with a different secret', () => {
    const mine = new CryptoEnvelope(SECRET);
    const theirs = new CryptoEnvelope('b'.repeat(64));
    assert.throws(() => mine.decrypt(theirs.encrypt('{}')), PwfCryptoError);
});

test('rejects a tampered ciphertext', () => {
    const env = new CryptoEnvelope(SECRET);
    const o = JSON.parse(env.encrypt('{"amount":1}'));
    const buf = Buffer.from(o.p, 'base64');
    buf[buf.length - 1] ^= 0xff;                       // flip a bit in the last block
    o.p = buf.toString('base64');
    assert.throws(() => env.decrypt(JSON.stringify(o)), PwfCryptoError);
});

test('rejects a stale timestamp (replay window)', () => {
    const env = new CryptoEnvelope(SECRET, 300);
    const o = JSON.parse(env.encrypt('{}'));
    o.t -= 400;
    // Re-sign so it fails on drift, not on the HMAC — otherwise the test proves nothing.
    const macKey = createHash('sha256').update('mac:' + SECRET, 'utf8').digest();
    o.s = createHmac('sha256', macKey).update(o.p + o.t, 'utf8').digest('hex');
    assert.throws(() => env.decrypt(JSON.stringify(o)), /timestamp is outside/);
});

test('rejects malformed envelopes', () => {
    const env = new CryptoEnvelope(SECRET);
    for (const bad of ['not json', '{}', '[]', '{"p":"x"}', 'null']) {
        assert.throws(() => env.decrypt(bad), PwfCryptoError, `should reject: ${bad}`);
    }
});

test('looksLikeEnvelope discriminates', () => {
    assert.equal(CryptoEnvelope.looksLikeEnvelope(new CryptoEnvelope(SECRET).encrypt('{}')), true);
    assert.equal(CryptoEnvelope.looksLikeEnvelope('{"success":true}'), false);
    assert.equal(CryptoEnvelope.looksLikeEnvelope('<html>502</html>'), false);
    assert.equal(CryptoEnvelope.looksLikeEnvelope(''), false);
});

test('key derivation matches the documented scheme', () => {
    // Independently derive and verify the signature the codec produced.
    const env = new CryptoEnvelope(SECRET);
    const o = JSON.parse(env.encrypt('{}'));
    const macKey = createHash('sha256').update('mac:' + SECRET, 'utf8').digest();
    assert.equal(createHmac('sha256', macKey).update(o.p + o.t, 'utf8').digest('hex'), o.s);
});

test('requires a secret', () => {
    assert.throws(() => new CryptoEnvelope(''), TypeError);
});
