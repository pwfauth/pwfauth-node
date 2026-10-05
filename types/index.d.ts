/// <reference types="node" />
import { EventEmitter } from 'node:events';

export interface PwfClientOptions {
    /** The 64-character hex secret from your dashboard. Never ship it to a browser. */
    appSecret: string;
    /** @default 'https://pwfauth.com' */
    baseUrl?: string;
    /** Override the machine fingerprint. Defaults to {@link getHardwareId}. */
    hardwareId?: string;
    /** @default 15000 */
    timeoutMs?: number;
    /**
     * Beats in a row without an encrypted answer (no reply, a plain refusal, a forged plain
     * success) before the client ends the session with NETWORK_LOST or CLOCK_SKEW. @default 3
     */
    maxHeartbeatFailures?: number;
    /** Separate budget for beats answered with HTTP 429. @default 10 */
    maxRateLimitedBeats?: number;
    /** Repair a wrong system clock from the server's time and retry once. @default true */
    autoCorrectClock?: boolean;
    /** @default 'pwfauth-node/<version> (+https://pwfauth.com)' */
    userAgent?: string;
    /** Must match the server. @default 300 */
    maxClockDriftSeconds?: number;
    /** Inject a fetch implementation (tests, proxies). Defaults to global fetch. */
    fetch?: typeof fetch;
}

/** The licence block from a login reply, with dates already parsed. */
export interface PwfLicense {
    licenseKey?: string;
    keyType?: string;
    duration?: number;
    hwid?: string;
    activatedAt: Date | null;
    /** `null` for lifetime keys — the server sends `expires_at: null`. */
    expiresAt: Date | null;
    /** `null` for lifetime keys. */
    daysRemaining: number | null;
    status?: string;
    /** True when the key never expires. */
    isLifetime: boolean;
}

export interface SessionEndedEvent {
    /** One of {@link PwfErrorCodes}. `NETWORK_LOST` and `CLOCK_SKEW` are raised by the client, not the server. */
    errorCode: string;
    /** Safe to show the end user. */
    message: string;
}

export interface RequestOptions {
    signal?: AbortSignal;
}

/** One API reply. */
export declare class PwfResponse {
    constructor(data: Record<string, any>, rawJson: string, isEnveloped?: boolean, statusCode?: number);
    static parse(json: string, opts?: { isEnveloped?: boolean; statusCode?: number }): PwfResponse;
    /** The parsed JSON body — use it for endpoint-specific fields. */
    readonly data: Record<string, any>;
    readonly rawJson: string;
    /** True when the reply was encrypted — only the license server can seal one. */
    readonly isEnveloped: boolean;
    /** The HTTP status (0 when unknown). */
    readonly statusCode: number;
    readonly success: boolean;
    readonly errorCode: string | undefined;
    readonly message: string | undefined;
    /** Parsed licence details, or null when the reply carries no `user` block. */
    readonly license: PwfLicense | null;
    /** Per-key feature flags. Empty object when absent. */
    readonly features: Record<string, unknown>;
    toString(): string;
}

export declare class PwfClient extends EventEmitter {
    constructor(secretOrOptions: string | PwfClientOptions);

    readonly isSignedIn: boolean;
    hardwareId: string;
    sessionId: string | null;
    licenseKey: string | null;
    heartbeatIntervalSeconds: number;
    /** How far this client shifts its clock to match the server (0 normally). */
    readonly clockOffsetSeconds: number;

    on(event: 'sessionEnded', listener: (e: SessionEndedEvent) => void): this;
    once(event: 'sessionEnded', listener: (e: SessionEndedEvent) => void): this;
    off(event: 'sessionEnded', listener: (e: SessionEndedEvent) => void): this;

    login(licenseKey: string, opts?: RequestOptions): Promise<PwfResponse>;
    checkKey(licenseKey: string, opts?: RequestOptions): Promise<PwfResponse>;
    heartbeat(opts?: RequestOptions): Promise<PwfResponse>;
    /** Starts the kill-switch loop. Without it a revoked licence keeps running. */
    startHeartbeat(): void;
    stopHeartbeat(): void;
    logout(opts?: RequestOptions): Promise<PwfResponse | null>;

    getAppInfo(opts?: RequestOptions): Promise<PwfResponse>;
    getTexts(opts?: RequestOptions): Promise<PwfResponse>;
    getSlides(opts?: RequestOptions): Promise<PwfResponse>;
    checkUpdate(currentVersion: string, channel?: string, opts?: RequestOptions): Promise<PwfResponse>;
    trackSocialClick(linkId: number, opts?: RequestOptions): Promise<PwfResponse>;

    createTrial(opts?: RequestOptions): Promise<PwfResponse>;
    /**
     * Moves a license to this PC (self-service): unbinds the key from every machine and
     * ends its sessions, so the next login() binds it here. The app's cooldown applies.
     */
    resetHardwareId(licenseKey: string, reason?: string, opts?: RequestOptions): Promise<PwfResponse>;
    /** @deprecated The dashboard does not show these requests. Use {@link resetHardwareId}. */
    requestHardwareReset(licenseKey: string, reason?: string, opts?: RequestOptions): Promise<PwfResponse>;

    registerAccount(username: string, password: string, email?: string, opts?: RequestOptions): Promise<PwfResponse>;
    /** Creates an account with an unused key: it takes the key's time and device limit, and the key is used up. */
    registerAccountWithKey(username: string, password: string, licenseKey: string, email?: string, opts?: RequestOptions): Promise<PwfResponse>;
    accountLogin(username: string, password: string, opts?: RequestOptions): Promise<PwfResponse>;
    /** Also signs the account out on every device. */
    changeAccountPassword(username: string, currentPassword: string, newPassword: string, opts?: RequestOptions): Promise<PwfResponse>;
    /** Adds an unused key's time to an account: pass the username and password, or neither to use the accountLogin() session. */
    redeemKey(licenseKey: string, username?: string | null, password?: string | null, opts?: RequestOptions): Promise<PwfResponse>;

    /** Escape hatches for endpoints this client does not wrap yet. */
    postEnvelope(path: string, body: Record<string, unknown>, opts?: RequestOptions): Promise<PwfResponse>;
    getEnvelope(path: string, bearerLicenseKey?: string | null, opts?: RequestOptions): Promise<PwfResponse>;
    postPlain(path: string, body: Record<string, unknown>, opts?: RequestOptions): Promise<PwfResponse>;
}

/** The AES-256-CBC + HMAC-SHA256 envelope codec. */
export declare class CryptoEnvelope {
    constructor(appSecret: string, maxDriftSeconds?: number);
    /** Seconds added to this machine's clock when stamping requests and checking replies. */
    clockOffsetSeconds: number;
    /** Unix time as the server sees it. */
    now(): number;
    encrypt(json: string): string;
    decrypt(envelopeJson: string): string;
    static looksLikeEnvelope(json: string): boolean;
}

export declare class PwfError extends Error {}
export declare class PwfHttpError extends PwfError {
    readonly status: number;
    readonly responseSnippet: string;
}
export declare class PwfCryptoError extends PwfError {}
/** An encrypted endpoint answered with an unencrypted "success" — not the license server. */
export declare class PwfSecurityError extends PwfError {}

/** This package's version, e.g. "1.1.0". */
export declare const VERSION: string;

export declare const PwfErrorCodes: Readonly<{
    MISSING_FIELDS: string; INVALID_KEY: string; INVALID_CREDENTIALS: string;
    HWID_MISMATCH: string; DEVICE_LIMIT: string; EXPIRED: string;
    BANNED: string; PAUSED: string; MAINTENANCE: string;
    SESSION_EXPIRED: string; SESSION_MISMATCH: string; SESSION_REVOKED: string;
    HWID_RESET: string; TRIAL_DISABLED: string; TRIAL_USED: string;
    TRIAL_LIMIT: string; OPEN_ACCESS_LIMIT: string;
    KEY_NOT_ACTIVE: string; NO_HWID: string; RATE_LIMITED: string; SELF_RESET_DISABLED: string;
    KEY_REQUIRED: string; KEY_ALREADY_USED: string; KEY_IN_USE: string; KEY_REDEEMED: string;
    ALREADY_LIFETIME: string; USERNAME_EXISTS: string; CRYPTO_ERROR: string;
    NETWORK_LOST: string; CLOCK_SKEW: string;
}>;

/** True when this code means the session is over and the app must sign the user out. */
export declare function endsSession(errorCode: string | null | undefined): boolean;

/** A stable per-machine identifier, matching the .NET client on the same machine. */
export declare function getHardwareId(): string;
