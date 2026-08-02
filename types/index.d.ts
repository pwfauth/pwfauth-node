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
    /** Consecutive unreachable beats before the client ends the session itself. @default 3 */
    maxHeartbeatFailures?: number;
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
    /** One of {@link PwfErrorCodes}. `NETWORK_LOST` is raised by the client, not the server. */
    errorCode: string;
    /** Safe to show the end user. */
    message: string;
}

export interface RequestOptions {
    signal?: AbortSignal;
}

/** One API reply. */
export declare class PwfResponse {
    constructor(data: Record<string, any>, rawJson: string);
    static parse(json: string): PwfResponse;
    /** The parsed JSON body — use it for endpoint-specific fields. */
    readonly data: Record<string, any>;
    readonly rawJson: string;
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
    requestHardwareReset(licenseKey: string, reason?: string, opts?: RequestOptions): Promise<PwfResponse>;

    registerAccount(username: string, password: string, email?: string, opts?: RequestOptions): Promise<PwfResponse>;
    accountLogin(username: string, password: string, opts?: RequestOptions): Promise<PwfResponse>;
    changeAccountPassword(username: string, currentPassword: string, newPassword: string, opts?: RequestOptions): Promise<PwfResponse>;

    /** Escape hatches for endpoints this client does not wrap yet. */
    postEnvelope(path: string, body: Record<string, unknown>, opts?: RequestOptions): Promise<PwfResponse>;
    getEnvelope(path: string, bearerLicenseKey?: string | null, opts?: RequestOptions): Promise<PwfResponse>;
    postPlain(path: string, body: Record<string, unknown>, opts?: RequestOptions): Promise<PwfResponse>;
}

/** The AES-256-CBC + HMAC-SHA256 envelope codec. */
export declare class CryptoEnvelope {
    constructor(appSecret: string, maxDriftSeconds?: number);
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

export declare const PwfErrorCodes: Readonly<{
    MISSING_FIELDS: string; INVALID_KEY: string; INVALID_CREDENTIALS: string;
    HWID_MISMATCH: string; DEVICE_LIMIT: string; EXPIRED: string;
    BANNED: string; PAUSED: string; MAINTENANCE: string;
    SESSION_EXPIRED: string; SESSION_MISMATCH: string; SESSION_REVOKED: string;
    HWID_RESET: string; TRIAL_DISABLED: string; TRIAL_USED: string;
    TRIAL_LIMIT: string; NETWORK_LOST: string;
}>;

/** True when this code means the session is over and the app must sign the user out. */
export declare function endsSession(errorCode: string | null | undefined): boolean;

/** A stable per-machine identifier, matching the .NET client on the same machine. */
export declare function getHardwareId(): string;
