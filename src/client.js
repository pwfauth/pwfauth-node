import { EventEmitter } from 'node:events';
import { CryptoEnvelope } from './envelope.js';
import { PwfError, PwfHttpError } from './errors.js';
import { endsSession, PwfErrorCodes } from './errorCodes.js';
import { getHardwareId } from './hardwareId.js';

const SNIPPET = 200;

/**
 * One API reply. The API returns open-ended JSON (fields differ per endpoint and grow
 * over time), so the whole document stays reachable through `data` while the fields
 * every reply carries get named accessors.
 */
export class PwfResponse {
    /** @param {object} data The parsed JSON body. */
    constructor(data, rawJson) {
        this.data = data;
        this.rawJson = rawJson;
    }

    static parse(json) {
        let data;
        try {
            data = JSON.parse(json);
        } catch (cause) {
            throw new PwfError('The license server returned a body that is not valid JSON.', { cause });
        }
        if (data === null || typeof data !== 'object' || Array.isArray(data)) {
            throw new PwfError('The license server returned a body that is not a JSON object.');
        }
        return new PwfResponse(data, json);
    }

    /** True when the API reported success. */
    get success() { return this.data.success === true; }

    /** Machine-readable failure reason, or undefined on success. Compare with {@link PwfErrorCodes}. */
    get errorCode() { return typeof this.data.error_code === 'string' ? this.data.error_code : undefined; }

    /** Human-readable message, safe to show the end user. */
    get message() { return typeof this.data.message === 'string' ? this.data.message : undefined; }

    /**
     * The licence block from a login reply.
     *
     * `expiresAt` is null for lifetime keys — the server sends `expires_at: null`, and
     * treating that as a date is the single most common integration bug.
     *
     * @returns {{licenseKey?:string, keyType?:string, duration?:number, hwid?:string,
     *            activatedAt:Date|null, expiresAt:Date|null, daysRemaining:number|null,
     *            status?:string, isLifetime:boolean}|null}
     */
    get license() {
        const u = this.data.user;
        if (!u || typeof u !== 'object') return null;
        const expiresAt = toDate(u.expires_at);
        return {
            licenseKey: u.license_key,
            keyType: u.key_type,
            duration: u.duration,
            hwid: u.hwid,
            activatedAt: toDate(u.activated_at),
            expiresAt,
            daysRemaining: typeof u.days_remaining === 'number' ? u.days_remaining : null,
            status: u.status,
            isLifetime: expiresAt === null,
        };
    }

    /** Per-key feature flags, as a plain object. Empty when absent. */
    get features() {
        const f = this.data.features;
        return f && typeof f === 'object' && !Array.isArray(f) ? f : {};
    }

    toString() { return this.message ?? this.errorCode ?? this.rawJson; }
}

function toDate(value) {
    if (typeof value !== 'string' || value === '') return null;
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * The PWF Auth client.
 *
 * Node only. The app secret must never reach a browser: whoever holds it can call the
 * API as your application. See the README's security note.
 *
 * Emits `sessionEnded` with `{ errorCode, message }` the moment the licence stops being
 * valid — ban, pause, expiry, HWID reset, revoke, maintenance, or the server going
 * unreachable. Sign the user out in that handler.
 *
 * @extends EventEmitter
 */
export class PwfClient extends EventEmitter {
    #options;
    #crypto;
    #heartbeatTimer = null;
    #heartbeatFailures = 0;
    #stopped = false;

    /**
     * @param {string|object} secretOrOptions The 64-char app secret, or an options object.
     * @param {string} [secretOrOptions.appSecret]
     * @param {string} [secretOrOptions.baseUrl='https://pwfauth.com']
     * @param {string} [secretOrOptions.hardwareId]  Override the machine fingerprint.
     * @param {number} [secretOrOptions.timeoutMs=15000]
     * @param {number} [secretOrOptions.maxHeartbeatFailures=3]
     * @param {number} [secretOrOptions.maxClockDriftSeconds=300]
     * @param {typeof fetch} [secretOrOptions.fetch] Inject a fetch implementation (tests, proxies).
     */
    constructor(secretOrOptions) {
        super();
        const o = typeof secretOrOptions === 'string' ? { appSecret: secretOrOptions } : { ...secretOrOptions };
        if (!o || !o.appSecret) throw new TypeError('appSecret is required.');

        this.#options = {
            baseUrl: 'https://pwfauth.com',
            timeoutMs: 15000,
            maxHeartbeatFailures: 3,
            maxClockDriftSeconds: 300,
            fetch: globalThis.fetch,
            ...o,
        };
        this.#options.baseUrl = String(this.#options.baseUrl).replace(/\/+$/, '');
        if (typeof this.#options.fetch !== 'function') {
            throw new TypeError('No fetch implementation available. Node 18+ is required, or pass options.fetch.');
        }

        this.#crypto = new CryptoEnvelope(this.#options.appSecret, this.#options.maxClockDriftSeconds);

        /** @type {string} */
        this.hardwareId = this.#options.hardwareId || getHardwareId();
        /** @type {string|null} */
        this.sessionId = null;
        /** @type {string|null} */
        this.licenseKey = null;
        /** @type {number} */
        this.heartbeatIntervalSeconds = 30;
    }

    /** True while a session is open. */
    get isSignedIn() { return this.sessionId !== null; }

    // ─────────────────── sessions ───────────────────

    /**
     * Activates the key on first use and opens a session.
     * @param {string} licenseKey e.g. XXXXX-XXXXX-XXXXX-XXXXX
     * @param {{signal?:AbortSignal}} [opts]
     */
    async login(licenseKey, opts = {}) {
        if (!licenseKey || !String(licenseKey).trim()) throw new TypeError('License key is required.');
        const res = await this.postEnvelope('/api/auth/login.php',
            { license_key: licenseKey, hwid: this.hardwareId }, opts);

        if (res.success) {
            this.licenseKey = licenseKey;
            this.sessionId = res.data.session_id ?? null;
            this.heartbeatIntervalSeconds = Math.max(5, Number(res.data.heartbeat_interval) || 30);
        }
        return res;
    }

    /**
     * Reads a key's status WITHOUT opening a session, so no device seat is consumed.
     * @param {string} licenseKey
     * @param {{signal?:AbortSignal}} [opts]
     */
    async checkKey(licenseKey, opts = {}) {
        if (!licenseKey) throw new TypeError('License key is required.');
        return this.postEnvelope('/api/auth/check-key.php', { license_key: licenseKey }, opts);
    }

    /**
     * Sends one heartbeat. Prefer {@link startHeartbeat} — a single beat proves nothing
     * about the next 30 seconds.
     * @param {{signal?:AbortSignal}} [opts]
     */
    async heartbeat(opts = {}) {
        if (!this.isSignedIn) throw new PwfError('No open session — call login() first.');
        return this.postEnvelope('/api/auth/heartbeat.php',
            { session_id: this.sessionId, license_key: this.licenseKey }, opts);
    }

    /**
     * Starts the background heartbeat loop. This is the enforcement point, not
     * bookkeeping: without it a revoked licence keeps running forever. Calling it twice
     * is a no-op.
     */
    startHeartbeat() {
        if (!this.isSignedIn) throw new PwfError('No open session — call login() first.');
        if (this.#heartbeatTimer) return;
        this.#stopped = false;
        this.#heartbeatFailures = 0;
        this.#scheduleBeat();
    }

    /** Stops the loop without ending the server session. */
    stopHeartbeat() {
        this.#stopped = true;
        if (this.#heartbeatTimer) {
            clearTimeout(this.#heartbeatTimer);
            this.#heartbeatTimer = null;
        }
    }

    #scheduleBeat() {
        if (this.#stopped || !this.isSignedIn) return;
        this.#heartbeatTimer = setTimeout(() => {
            this.#heartbeatTimer = null;
            this.#beat();
        }, this.heartbeatIntervalSeconds * 1000);
        // Never hold the process open just to beat.
        this.#heartbeatTimer.unref?.();
    }

    async #beat() {
        if (this.#stopped || !this.isSignedIn) return;

        let beat;
        try {
            beat = await this.heartbeat();
        } catch {
            // Transport failure: the server may be down, or someone may have blocked the
            // domain to keep the app running. Either way the server has dropped (or will
            // drop) the session, so we must not run forever.
            this.#heartbeatFailures++;
            if (this.#heartbeatFailures >= this.#options.maxHeartbeatFailures) {
                this.#endSession(PwfErrorCodes.NETWORK_LOST,
                    'Cannot reach the license server. Please check your connection and sign in again.');
                return;
            }
            this.#scheduleBeat();
            return;
        }

        this.#heartbeatFailures = 0;

        if (!beat.success && endsSession(beat.errorCode)) {
            this.#endSession(beat.errorCode, beat.message ?? 'Your session has ended.');
            return;
        }
        // Unknown non-success: treat as transient and keep beating.
        this.#scheduleBeat();
    }

    #endSession(errorCode, message) {
        this.stopHeartbeat();
        this.sessionId = null;
        this.emit('sessionEnded', { errorCode, message });
    }

    /**
     * Closes the session server-side and frees the device seat. Safe when already out.
     * @param {{signal?:AbortSignal}} [opts]
     */
    async logout(opts = {}) {
        if (!this.isSignedIn) return null;
        this.stopHeartbeat();

        const session = this.sessionId;
        const key = this.licenseKey ?? '';
        this.sessionId = null;

        try {
            return await this.postEnvelope('/api/auth/logout.php',
                { session_id: session, license_key: key }, opts);
        } catch (e) {
            if (e instanceof PwfError) return null;   // server reaps it on timeout anyway
            throw e;
        }
    }

    // ─────────────── app content & updates ───────────────

    /** App metadata: display name, current version, download URL, login message. */
    getAppInfo(opts = {}) { return this.getEnvelope('/api/app/info.php', null, opts); }

    /** Remote texts for the signed-in licence, per-key overrides applied. */
    async getTexts(opts = {}) {
        if (!this.licenseKey) throw new PwfError('Sign in first — remote texts are resolved per license key.');
        return this.getEnvelope('/api/app/text.php', this.licenseKey, opts);
    }

    /** The active announcement slides for this application. */
    getSlides(opts = {}) {
        return this.postEnvelope('/api/app/slides.php', { action: 'get_slides' }, opts);
    }

    /**
     * OTA update check.
     * @param {string} currentVersion e.g. "1.4.2"
     * @param {string} [channel='stable']
     */
    async checkUpdate(currentVersion, channel = 'stable', opts = {}) {
        if (!currentVersion) throw new TypeError('Current version is required.');
        return this.postEnvelope('/api/update/check.php', {
            v: currentVersion,
            channel: channel || 'stable',
            hwid: this.hardwareId,
            license_key: this.licenseKey ?? '',
        }, opts);
    }

    /** @param {number} linkId */
    trackSocialClick(linkId, opts = {}) {
        return this.postEnvelope('/api/app/social-click.php', { link_id: linkId }, opts);
    }

    // ─────────────── trials & self-service ───────────────

    /** Requests a free trial for this machine. */
    createTrial(opts = {}) {
        return this.postPlain('/api/auth/trial.php', { hwid: this.hardwareId }, opts);
    }

    /** Files a hardware-reset request for an admin to approve. */
    async requestHardwareReset(licenseKey, reason = 'Device changed', opts = {}) {
        if (!licenseKey) throw new TypeError('License key is required.');
        return this.postPlain('/api/auth/request-hwid-reset.php',
            { license_key: licenseKey, reason }, opts);
    }

    // ─────────────────── user accounts ───────────────────

    async registerAccount(username, password, email = '', opts = {}) {
        if (!username || !password) throw new TypeError('Username and password are required.');
        return this.postPlain('/api/auth/account-register.php', { username, password, email }, opts);
    }

    async accountLogin(username, password, opts = {}) {
        if (!username) throw new TypeError('Username is required.');
        const res = await this.postPlain('/api/auth/account-login.php',
            { username, password, hwid: this.hardwareId }, opts);
        if (res.success) {
            this.sessionId = res.data.session_id ?? null;
            this.licenseKey = res.data.license_key ?? null;
            this.heartbeatIntervalSeconds = Math.max(5, Number(res.data.heartbeat_interval) || 30);
        }
        return res;
    }

    changeAccountPassword(username, currentPassword, newPassword, opts = {}) {
        return this.postPlain('/api/auth/change-password.php',
            { username, current_password: currentPassword, new_password: newPassword }, opts);
    }

    // ─────────────────── transports ───────────────────
    // Public so endpoints this client has not wrapped yet stay reachable.

    /** POST with the AES envelope in both directions. */
    async postEnvelope(path, body, opts = {}) {
        return this.#send(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-App-Secret': this.#options.appSecret },
            body: this.#crypto.encrypt(JSON.stringify(body ?? {})),
        }, opts);
    }

    /** GET whose reply is enveloped. Pass a licence key for Bearer-authenticated endpoints. */
    async getEnvelope(path, bearerLicenseKey = null, opts = {}) {
        const headers = { 'X-App-Secret': this.#options.appSecret };
        if (bearerLicenseKey) headers.Authorization = 'Bearer ' + bearerLicenseKey;
        return this.#send(path, { method: 'GET', headers }, opts);
    }

    /** POST plain JSON — trials, hardware-reset requests, user accounts. */
    async postPlain(path, body, opts = {}) {
        return this.#send(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-App-Secret': this.#options.appSecret },
            body: JSON.stringify(body ?? {}),
        }, opts);
    }

    async #send(path, init, opts) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.#options.timeoutMs);
        // Honour a caller's signal without losing our own timeout.
        const onAbort = () => controller.abort();
        opts.signal?.addEventListener('abort', onAbort, { once: true });

        let response;
        try {
            response = await this.#options.fetch(this.#options.baseUrl + path,
                { ...init, signal: controller.signal });
        } catch (cause) {
            if (opts.signal?.aborted) throw cause;    // caller cancelled — surface as-is
            throw new PwfHttpError(0, 'The license server did not respond in time.', '', { cause });
        } finally {
            clearTimeout(timer);
            opts.signal?.removeEventListener('abort', onAbort);
        }

        const status = response.status;
        const raw = await response.text();

        if (!raw || !raw.trim()) {
            throw new PwfHttpError(status, `License server returned HTTP ${status} with an empty body.`);
        }

        if (CryptoEnvelope.looksLikeEnvelope(raw)) {
            return PwfResponse.parse(this.#crypto.decrypt(raw));
        }

        let plain;
        try {
            plain = PwfResponse.parse(raw);
        } catch {
            // Not JSON at all — nearly always a proxy/CDN error page or a wrong base URL.
            throw new PwfHttpError(status,
                `License server returned HTTP ${status} with a non-JSON body. Check the API base URL.`,
                raw.slice(0, SNIPPET));
        }

        // The API answers failures with its own {success,error_code,message} shape; hand
        // those back so callers can react. Anything else with a failing status is a
        // transport problem, not an API answer.
        if (status >= 400 && !('success' in plain.data)) {
            throw new PwfHttpError(status, `License server returned HTTP ${status}.`, raw.slice(0, SNIPPET));
        }
        return plain;
    }
}
