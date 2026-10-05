import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { PwfCryptoError } from './errors.js';

/**
 * The AES-256-CBC + HMAC-SHA256 envelope the SDK-grade endpoints speak.
 *
 * Wire format: `{"p": base64(IV || ciphertext), "t": unix, "s": hmac_hex(p + t)}`.
 * Both keys derive from the app secret, so there is no separate key exchange.
 * This mirrors the server's PayloadCrypto and the .NET client's CryptoEnvelope
 * byte for byte — the three must stay in lockstep.
 */
export class CryptoEnvelope {
    #encKey;
    #macKey;
    #maxDriftSeconds;

    /**
     * @param {string} appSecret       The 64-character hex secret from your dashboard.
     * @param {number} maxDriftSeconds How far a reply's timestamp may drift before it is
     *                                 rejected as a replay. Must match the server (300).
     */
    constructor(appSecret, maxDriftSeconds = 300) {
        if (!appSecret) throw new TypeError('App secret is required.');
        this.#encKey = createHash('sha256').update('enc:' + appSecret, 'utf8').digest();
        this.#macKey = createHash('sha256').update('mac:' + appSecret, 'utf8').digest();
        this.#maxDriftSeconds = maxDriftSeconds;
        /**
         * Seconds added to this machine's clock when stamping requests and checking
         * replies. The client sets it from the server's time when the server refuses a
         * request because this machine's clock is wrong.
         * @type {number}
         */
        this.clockOffsetSeconds = 0;
    }

    /** Unix time as the server sees it: this machine's clock plus the offset. */
    now() {
        return Math.floor(Date.now() / 1000) + Math.trunc(this.clockOffsetSeconds);
    }

    /**
     * Encrypts a request body into the wire envelope.
     * @param {string} json The plain JSON body to protect.
     * @returns {string} The `{p,t,s}` document to send.
     */
    encrypt(json) {
        if (typeof json !== 'string') throw new TypeError('json must be a string.');

        const iv = randomBytes(16);
        const cipher = createCipheriv('aes-256-cbc', this.#encKey, iv);   // PKCS#7 by default
        const encrypted = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);

        const p = Buffer.concat([iv, encrypted]).toString('base64');
        const t = this.now();
        return JSON.stringify({ p, t, s: this.#hmacHex(p + t) });
    }

    /**
     * Verifies and decrypts a wire envelope back into plain JSON.
     * @param {string} envelopeJson The `{p,t,s}` document the server returned.
     * @returns {string} The decrypted JSON body.
     * @throws {PwfCryptoError} Signature failed, timestamp drifted, or payload malformed.
     */
    decrypt(envelopeJson) {
        let p, t, s;
        try {
            ({ p, t, s } = JSON.parse(envelopeJson));
            if (typeof p !== 'string' || typeof s !== 'string' || typeof t !== 'number') {
                throw new Error('missing fields');
            }
        } catch (cause) {
            throw new PwfCryptoError('Invalid envelope format.', { cause });
        }

        if (!this.#fixedTimeEquals(this.#hmacHex(p + t), s)) {
            throw new PwfCryptoError(
                'HMAC verification failed — wrong app secret, or the payload was tampered with.');
        }

        if (Math.abs(this.now() - t) > this.#maxDriftSeconds) {
            throw new PwfCryptoError(
                "Envelope timestamp is outside the accepted window — check this machine's system clock.");
        }

        const combined = Buffer.from(p, 'base64');
        if (combined.length <= 16) throw new PwfCryptoError('Malformed ciphertext.');

        try {
            const decipher = createDecipheriv('aes-256-cbc', this.#encKey, combined.subarray(0, 16));
            return Buffer.concat([decipher.update(combined.subarray(16)), decipher.final()]).toString('utf8');
        } catch (cause) {
            throw new PwfCryptoError('Decryption failed — wrong app secret or corrupted payload.', { cause });
        }
    }

    /**
     * True when the document looks like a `{p,t,s}` envelope.
     * @param {string} json Any JSON body.
     */
    static looksLikeEnvelope(json) {
        if (!json) return false;
        try {
            const o = JSON.parse(json);
            return !!o && typeof o === 'object' && !Array.isArray(o) && 'p' in o && 't' in o && 's' in o;
        } catch {
            return false;
        }
    }

    #hmacHex(message) {
        return createHmac('sha256', this.#macKey).update(message, 'utf8').digest('hex');
    }

    /**
     * Compares two hex signatures without an early exit. A plain `===` leaks, through
     * timing, how many leading characters matched — enough to walk a forged signature
     * into place one character at a time.
     */
    #fixedTimeEquals(a, b) {
        if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
        return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
    }
}
