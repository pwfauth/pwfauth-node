import { EventEmitter } from 'node:events';
import { CryptoEnvelope } from './envelope.js';
import { PwfError, PwfHttpError, PwfSecurityError } from './errors.js';
import { endsSession, PwfErrorCodes } from './errorCodes.js';
import { getHardwareId } from './hardwareId.js';

export const VERSION = '1.1.0';

const SNIPPET = 200;
const TOO_MANY_REQUESTS = 429;
const DEFAULT_RESET_REASON = 'Reset from app';
const MAX_RESET_REASON = 255;
const NETWORK_LOST_MESSAGE = 'Cannot reach the license server. Please check your connection and sign in again.';
const CLOCK_SKEW_MESSAGE = "Cannot verify your license because this computer's date and time are wrong. Correct them and sign in again.";

/**
 * One API reply. The API returns open-ended JSON (fields differ per endpoint and grow
 * over time), so the whole document stays reachable through `data` while the fields
 * every reply carries get named accessors.
 */
export class PwfResponse {
    /**
     * @param {object} data The parsed JSON body.
     * @param {string} rawJson
     * @param {boolean} [isEnveloped] True when the reply was an encrypted envelope.
     * @param {number} [statusCode] The HTTP status.
     */
    constructor(data, rawJson, isEnveloped = false, statusCode = 0) {
        this.data = data;
        this.rawJson = rawJson;
        /** Only the license server can seal a reply, so only an encrypted one proves it answered. */
        this.isEnveloped = isEnveloped;
        this.statusCode = statusCode;
    }

    static parse(json, { isEnveloped = false, statusCode = 0 } = {}) {
        let data;
        try {
            data = JSON.parse(json);
        } catch (cause) {
            throw new PwfError('The license server returned a body that is not valid JSON.', { cause });
        }
        if (data === null || typeof data !== 'object' || Array.isArray(data)) {
            throw new PwfError('The license server returned a body that is not a JSON object.');
        }
        return new PwfResponse(data, json, isEnveloped, statusCode);
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

/** A plain refusal that blames this computer's clock (the server's replay check). */
function isClockRefusal(reply) {
    if (reply.data.reason === PwfErrorCodes.CLOCK_SKEW) return true;
    return reply.errorCode === PwfErrorCodes.CRYPTO_ERROR && /expired/i.test(reply.message ?? '');
}

let deprecationWarned = false;

/**
 * The PWF Auth client.
 *
 * Node only. The app secret must never reach a browser: whoever holds it can call the
 * API as your application. See the README's security note.
 *
 * Emits `sessionEnded` with `{ errorCode, message }` the moment the licence stops being
 * valid — ban, pause, expiry, HWID reset, revoke, maintenance, a password change on an
 * account, or a server that stopped answering. Sign the user out in that handler.
 *
 * @extends EventEmitter
 */
export class PwfClient extends EventEmitter {
    #options;
    #crypto;
    #heartbeatTimer = null;
    #loop = null;          // the running loop's state; replaced on every start/stop

    /**
     * @param {string|object} secretOrOptions The 64-char app secret, or an options object.
     * @param {string} [secretOrOptions.appSecret]
     * @param {string} [secretOrOptions.baseUrl='https://pwfauth.com']
     * @param {string} [secretOrOptions.hardwareId]  Override the machine fingerprint.
     * @param {number} [secretOrOptions.timeoutMs=15000]
     * @param {number} [secretOrOptions.maxHeartbeatFailures=3] Beats in a row without an
     *        encrypted answer (no reply, or only a plain refusal) before NETWORK_LOST.
     * @param {number} [secretOrOptions.maxRateLimitedBeats=10] Separate budget for HTTP 429.
     * @param {boolean} [secretOrOptions.autoCorrectClock=true] Repair a wrong system clock
     *        from the server's time and retry once.
     * @param {number} [secretOrOptions.maxClockDriftSeconds=300]
     * @param {string} [secretOrOptions.userAgent]
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
            maxRateLimitedBeats: 10,
            autoCorrectClock: true,
            maxClockDriftSeconds: 300,
            userAgent: `pwfauth-node/${VERSION} (+https://pwfauth.com)`,
            fetch: globalThis.fetch,
            ...o,
        };
        this.#options.appSecret = String(this.#options.appSecret).trim();
        this.#options.baseUrl = String(this.#options.baseUrl).replace(/\/+$/, '');
        if (!/^https?:\/\/[^/]+/i.test(this.#options.baseUrl)) {
            throw new TypeError('baseUrl must be an absolute URL, e.g. https://pwfauth.com');
        }
        if (!(this.#options.maxHeartbeatFailures >= 1)) {
            throw new RangeError('maxHeartbeatFailures must be at least 1, otherwise an unreachable server leaves the app running forever.');
        }
        if (!(this.#options.maxRateLimitedBeats >= 1)) {
            throw new RangeError('maxRateLimitedBeats must be at least 1, otherwise a proxy answering 429 forever leaves the app running.');
        }
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
        /** Seconds between heartbeats, as the server says at login. @type {number} */
        this.heartbeatIntervalSeconds = 30;
    }

    /** True while a session is open. */
    get isSignedIn() { return this.sessionId !== null; }

    /** How far this client shifts its clock to match the server (0 normally). */
    get clockOffsetSeconds() { return this.#crypto.clockOffsetSeconds; }

    // ─────────────────── sessions ───────────────────

    /**
     * Activates the key on first use and opens a session.
     *
     * When the key is bound to another machine the reply carries `HWID_MISMATCH`
     * (`DEVICE_LIMIT` for multi-device keys): {@link resetHardwareId} lets the customer
     * move it here, then call this again.
     *
     * Rejects with PwfSecurityError on an unencrypted "success" (not the license server),
     * PwfHttpError when there is no usable reply, PwfCryptoError when the reply fails
     * verification (usually the wrong app secret).
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
     * bookkeeping: without it a revoked licence keeps running forever.
     *
     * It keeps the session alive AND obeys the kill switch: a ban, pause, expiry, HWID
     * reset, revoke or maintenance window emits `sessionEnded` on the next beat. So does
     * losing the server: only an encrypted reply counts as an answer, and
     * `maxHeartbeatFailures` beats in a row without one — no reply, a forged plain
     * "success", or a plain refusal — end the session with NETWORK_LOST, or CLOCK_SKEW
     * when the server kept rejecting this computer's clock. Calling it twice is a no-op.
     */
    startHeartbeat() {
        if (!this.isSignedIn) throw new PwfError('No open session — call login() first.');
        if (this.#loop) return;
        this.#loop = { unanswered: 0, plainRefusals: 0, clockRefusals: 0, rateLimited: 0 };
        this.#scheduleBeat(this.#loop);
    }

    /** Stops the loop without ending the server session. A beat in flight is ignored. */
    stopHeartbeat() {
        this.#loop = null;
        if (this.#heartbeatTimer) {
            clearTimeout(this.#heartbeatTimer);
            this.#heartbeatTimer = null;
        }
    }

    #scheduleBeat(loop) {
        if (this.#loop !== loop || !this.isSignedIn) return;
        this.#heartbeatTimer = setTimeout(() => {
            this.#heartbeatTimer = null;
            this.#beat(loop);
        }, this.heartbeatIntervalSeconds * 1000);
        // Never hold the process open just to beat.
        this.#heartbeatTimer.unref?.();
    }

    async #beat(loop) {
        if (this.#loop !== loop || !this.isSignedIn) return;

        // Only an encrypted reply proves the license server answered — nothing else can
        // seal one. Every other outcome is an unanswered beat: no reply, a reply that fails
        // verification, a forged plain "success" (PwfSecurityError), and plain refusals,
        // which the server sends when it cannot verify the request at all. The commonest of
        // those is its replay check rejecting a clock more than five minutes off; treating
        // it as transient (as 1.0.0 did) let an app whose clock was moved run forever,
        // deaf to bans.
        let beat = null;
        let error = null;
        try {
            beat = await this.heartbeat();
        } catch (e) {
            error = e;
        }
        // Stopped or signed out while the beat was in flight: say nothing.
        if (this.#loop !== loop || !this.isSignedIn) return;

        if (error) {
            if (error instanceof PwfHttpError && error.status === TOO_MANY_REQUESTS) {
                if (++loop.rateLimited >= this.#options.maxRateLimitedBeats) {
                    this.#endSession(PwfErrorCodes.NETWORK_LOST, NETWORK_LOST_MESSAGE);
                    return;
                }
                this.#scheduleBeat(loop);
                return;
            }
            // Transport failure: the server may be down, or someone may have blocked the
            // domain to keep the app running. Either way it will not keep this session alive.
            if (++loop.unanswered >= this.#options.maxHeartbeatFailures) {
                this.#endUnanswered(loop);
                return;
            }
            this.#scheduleBeat(loop);
            return;
        }

        if (!beat.isEnveloped) {
            // A plain reply is a refusal (a plain success threw above). Shared IPs get rate
            // limited legitimately, so 429 has its own, larger budget.
            if (beat.statusCode === TOO_MANY_REQUESTS) {
                if (++loop.rateLimited >= this.#options.maxRateLimitedBeats) {
                    this.#endSession(PwfErrorCodes.NETWORK_LOST, NETWORK_LOST_MESSAGE);
                    return;
                }
                this.#scheduleBeat(loop);
                return;
            }
            loop.plainRefusals++;
            if (isClockRefusal(beat)) loop.clockRefusals++;
            if (++loop.unanswered >= this.#options.maxHeartbeatFailures) {
                this.#endUnanswered(loop);
                return;
            }
            this.#scheduleBeat(loop);
            return;
        }

        // Encrypted: the server is reachable and the clock is fine. Every count starts over —
        // and neither kind of failure ever resets the other, so alternating them cannot keep
        // the loop alive either.
        loop.unanswered = loop.plainRefusals = loop.clockRefusals = loop.rateLimited = 0;

        if (!beat.success && endsSession(beat.errorCode)) {
            this.#endSession(beat.errorCode, beat.message ?? 'Your session has ended.');
            return;
        }
        // Success, or an unknown encrypted failure (transient): keep beating.
        this.#scheduleBeat(loop);
    }

    #endUnanswered(loop) {
        // When every plain refusal in the streak blamed the clock, say so: signing in again
        // cannot work until it is corrected.
        if (loop.plainRefusals > 0 && loop.clockRefusals === loop.plainRefusals) {
            this.#endSession(PwfErrorCodes.CLOCK_SKEW, CLOCK_SKEW_MESSAGE);
        } else {
            this.#endSession(PwfErrorCodes.NETWORK_LOST, NETWORK_LOST_MESSAGE);
        }
    }

    #endSession(errorCode, message) {
        this.stopHeartbeat();
        this.sessionId = null;
        this.emit('sessionEnded', { errorCode, message });
    }

    /**
     * Stops the heartbeat and ends the session on the server. Safe when already signed
     * out. Resolves to null when there was no session or the server could not be reached
     * (it then ends the session on its own timeout).
     *
     * Logging out does not unbind the key: it stays bound to this machine. To move the
     * license to another computer, use {@link resetHardwareId}.
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

    /** @param {number} linkId The link's numeric id from getAppInfo() (`data.app.social_links[].id`). */
    async trackSocialClick(linkId, opts = {}) {
        const id = typeof linkId === 'string' && linkId.trim() !== '' ? Number(linkId) : linkId;
        if (!Number.isInteger(id) || id <= 0) throw new TypeError("linkId must be the link's numeric id from getAppInfo().");
        return this.postEnvelope('/api/app/social-click.php', { link_id: id }, opts);
    }

    // ─────────────── trials & self-service ───────────────

    /** Requests a free trial for this machine. */
    createTrial(opts = {}) {
        return this.postPlain('/api/auth/trial.php', { hwid: this.hardwareId }, opts);
    }

    /**
     * Moves a license to a new PC, instantly and without waiting for the developer:
     * unbinds the key from every machine it is bound to, so the next {@link login} binds
     * it to this one, and ends all of its sessions. The developer decides whether
     * self-service moves are allowed and the cooldown between two of them (12 hours by
     * default). Typical flow: login() fails with HWID_MISMATCH or DEVICE_LIMIT → the user
     * confirms → resetHardwareId() → login().
     *
     * Refusals: INVALID_KEY, KEY_NOT_ACTIVE, NO_HWID, RATE_LIMITED (the message says how
     * many hours to wait) or SELF_RESET_DISABLED. On success `data.next_reset_at` says when
     * the next move is allowed.
     * @param {string} licenseKey
     * @param {string} [reason] Stored with the reset, e.g. "New laptop". At most 255 chars.
     */
    async resetHardwareId(licenseKey, reason = '', opts = {}) {
        if (!licenseKey || !String(licenseKey).trim()) throw new TypeError('License key is required.');
        // Cut by code points so an emoji is never split into a lone surrogate.
        const text = Array.from(String(reason ?? '').trim() || DEFAULT_RESET_REASON).slice(0, MAX_RESET_REASON).join('');
        return this.postPlain('/api/customer/reset-hwid.php',
            { key: String(licenseKey).trim(), reason: text }, opts);
    }

    /**
     * Deprecated: files a reset request that nobody can approve yet, because the dashboard
     * does not show these requests. Use {@link resetHardwareId}.
     */
    async requestHardwareReset(licenseKey, reason = 'Device changed', opts = {}) {
        if (!deprecationWarned) {
            deprecationWarned = true;
            process.emitWarning('requestHardwareReset() is deprecated: use resetHardwareId() for an instant self-service move.',
                { type: 'DeprecationWarning', code: 'PWFAUTH_REQUEST_RESET' });
        }
        if (!licenseKey) throw new TypeError('License key is required.');
        return this.postPlain('/api/auth/request-hwid-reset.php',
            { license_key: licenseKey, reason }, opts);
    }

    // ─────────────────── user accounts ───────────────────

    /**
     * Creates an end-user account. An app that wants a license key at sign-up answers
     * KEY_REQUIRED: use {@link registerAccountWithKey}.
     */
    async registerAccount(username, password, email = '', opts = {}) {
        if (!username || !password) throw new TypeError('Username and password are required.');
        return this.postPlain('/api/auth/account-register.php', { username, password, email: email ?? '' }, opts);
    }

    /**
     * Creates an account with an unused license key: the account gets the key's time and
     * device limit, and the key turns `redeemed` (it can no longer sign in on its own).
     * Refusals: INVALID_KEY, KEY_ALREADY_USED, KEY_IN_USE, BANNED, PAUSED, EXPIRED,
     * USERNAME_EXISTS.
     */
    async registerAccountWithKey(username, password, licenseKey, email = '', opts = {}) {
        if (!username || !password) throw new TypeError('Username and password are required.');
        if (!licenseKey || !String(licenseKey).trim()) throw new TypeError('License key is required.');
        return this.postPlain('/api/auth/account-register.php',
            { username, password, email: email ?? '', license_key: String(licenseKey).trim() }, opts);
    }

    /** Signs an account in and opens a session bound to this machine — the heartbeat applies as after login(). */
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

    /**
     * Changes an account's password. This signs the account out on every device, this one
     * included: a running heartbeat reports it through `sessionEnded`.
     */
    async changeAccountPassword(username, currentPassword, newPassword, opts = {}) {
        if (!username || !currentPassword || !newPassword) {
            throw new TypeError('username, currentPassword and newPassword are required.');
        }
        return this.postPlain('/api/auth/change-password.php',
            { username, current_password: currentPassword, new_password: newPassword }, opts);
    }

    /**
     * Adds an unused key's time to an account, and uses the key up. Pass the username and
     * password (works while the account has expired too), or neither to use the account
     * signed in with {@link accountLogin}. The app's settings decide whether the time goes
     * on top or starts from now. The reply carries `days_added`, `lifetime`, `expires_at`,
     * `days_remaining` and `max_devices`. Wrong passwords and unknown keys count toward the
     * sign-in lockout (HTTP 429).
     * @param {string} licenseKey
     * @param {string|null} [username]
     * @param {string|null} [password]
     */
    async redeemKey(licenseKey, username = null, password = null, opts = {}) {
        if (!licenseKey || !String(licenseKey).trim()) throw new TypeError('License key is required.');
        const key = String(licenseKey).trim();
        if (username || password) {
            if (!username || !password) throw new TypeError('Pass both username and password, or neither.');
            return this.postPlain('/api/auth/account-redeem.php', { username, password, license_key: key }, opts);
        }
        if (!this.isSignedIn) {
            throw new PwfError('No account is signed in: call accountLogin() first, or pass the username and password.');
        }
        return this.postPlain('/api/auth/account-redeem.php', { session_id: this.sessionId, license_key: key }, opts);
    }

    // ─────────────────── transports ───────────────────
    // Public so endpoints this client has not wrapped yet stay reachable.

    /**
     * POST with the AES envelope in both directions. A plain JSON failure (a bad app
     * secret, a rate limit) is returned as a failed reply; a plain JSON *success* rejects
     * with PwfSecurityError. When the server refuses this machine's clock it sends its own
     * time: the client shifts its clock by the difference and sends the request once more.
     */
    async postEnvelope(path, body, opts = {}) {
        let reply = await this.#postEnvelopeOnce(path, body, opts);
        if (this.#options.autoCorrectClock && this.#tryCorrectClock(reply)) {
            reply = await this.#postEnvelopeOnce(path, body, opts);
        }
        return reply;
    }

    /** GET whose reply is enveloped. Pass a licence key for Bearer-authenticated endpoints. */
    async getEnvelope(path, bearerLicenseKey = null, opts = {}) {
        const headers = { 'X-App-Secret': this.#options.appSecret };
        if (bearerLicenseKey) headers.Authorization = 'Bearer ' + bearerLicenseKey;
        return this.#send(path, { method: 'GET', headers }, opts, true);
    }

    /** POST plain JSON — trials, hardware resets, user accounts. */
    async postPlain(path, body, opts = {}) {
        return this.#send(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-App-Secret': this.#options.appSecret },
            body: JSON.stringify(body ?? {}),
        }, opts, false);
    }

    #postEnvelopeOnce(path, body, opts) {
        return this.#send(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-App-Secret': this.#options.appSecret },
            body: this.#crypto.encrypt(JSON.stringify(body ?? {})),
        }, opts, true);
    }

    // The server's plain refusal for a timestamp outside its window carries
    // "reason": "CLOCK_SKEW" and "server_time" (unix seconds). It never sends that refusal
    // encrypted, so only a plain reply qualifies.
    #tryCorrectClock(reply) {
        if (reply.isEnveloped || reply.data.reason !== PwfErrorCodes.CLOCK_SKEW) return false;
        const serverTime = reply.data.server_time;
        if (!Number.isInteger(serverTime) || serverTime <= 0) return false;
        this.#crypto.clockOffsetSeconds = serverTime - Math.floor(Date.now() / 1000);
        return true;
    }

    async #send(path, init, opts, requireEnvelope) {
        const controller = new AbortController();
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; controller.abort(); }, this.#options.timeoutMs);
        // Honour a caller's signal without losing our own timeout.
        const onAbort = () => controller.abort();
        opts.signal?.addEventListener('abort', onAbort, { once: true });

        const headers = { ...init.headers };
        if (this.#options.userAgent) headers['User-Agent'] = this.#options.userAgent;

        let response;
        let raw;
        try {
            response = await this.#options.fetch(this.#options.baseUrl + path,
                { ...init, headers, signal: controller.signal });
            raw = await response.text();
        } catch (cause) {
            if (opts.signal?.aborted) throw cause;    // caller cancelled — surface as-is
            const why = timedOut
                ? 'The license server did not respond in time.'
                : `Cannot reach the license server: ${cause?.cause?.message ?? cause?.message ?? cause}`;
            throw new PwfHttpError(0, why, '', { cause });
        } finally {
            clearTimeout(timer);
            opts.signal?.removeEventListener('abort', onAbort);
        }

        const status = response.status;

        if (!raw || !raw.trim()) {
            throw new PwfHttpError(status, `License server returned HTTP ${status} with an empty body.`);
        }

        if (CryptoEnvelope.looksLikeEnvelope(raw)) {
            return PwfResponse.parse(this.#crypto.decrypt(raw), { isEnveloped: true, statusCode: status });
        }

        let plain;
        try {
            plain = PwfResponse.parse(raw, { isEnveloped: false, statusCode: status });
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

        // Encrypted endpoints seal EVERY reply once the request is verified; only refusals
        // before that point travel as plain JSON, and those are all failures. A plain
        // success therefore came from a proxy, a hosts-file redirect or a fake server — and
        // accepting it would let any of them unlock the application.
        if (requireEnvelope && plain.success) {
            throw new PwfSecurityError("The license server's reply was not encrypted, so it cannot be trusted.");
        }
        return plain;
    }
}
