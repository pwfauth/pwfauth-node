/** Machine-readable failure reasons returned as `error_code`. */
export const PwfErrorCodes = Object.freeze({
    MISSING_FIELDS: 'MISSING_FIELDS',
    INVALID_KEY: 'INVALID_KEY',
    INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
    HWID_MISMATCH: 'HWID_MISMATCH',
    DEVICE_LIMIT: 'DEVICE_LIMIT',
    EXPIRED: 'EXPIRED',
    BANNED: 'BANNED',
    PAUSED: 'PAUSED',
    MAINTENANCE: 'MAINTENANCE',
    SESSION_EXPIRED: 'SESSION_EXPIRED',
    SESSION_MISMATCH: 'SESSION_MISMATCH',
    SESSION_REVOKED: 'SESSION_REVOKED',
    HWID_RESET: 'HWID_RESET',
    TRIAL_DISABLED: 'TRIAL_DISABLED',
    TRIAL_USED: 'TRIAL_USED',
    TRIAL_LIMIT: 'TRIAL_LIMIT',
    /** The application runs in open-access mode and reached its daily cap of new users. */
    OPEN_ACCESS_LIMIT: 'OPEN_ACCESS_LIMIT',

    // Self-service hardware reset (resetHardwareId).
    /** The key is expired, banned or paused, so it cannot be moved. */
    KEY_NOT_ACTIVE: 'KEY_NOT_ACTIVE',
    /** The key is not bound to any machine — nothing to reset. */
    NO_HWID: 'NO_HWID',
    /** Too many requests; from resetHardwareId: the cooldown has not passed yet. */
    RATE_LIMITED: 'RATE_LIMITED',
    /** The developer turned self-service moves off for this application. */
    SELF_RESET_DISABLED: 'SELF_RESET_DISABLED',

    // Accounts that run on license keys.
    /** The application wants a license key at sign-up: use registerAccountWithKey(). */
    KEY_REQUIRED: 'KEY_REQUIRED',
    /** The key was already added to an account. */
    KEY_ALREADY_USED: 'KEY_ALREADY_USED',
    /** The key was already activated by a license login, so it cannot go on an account. */
    KEY_IN_USE: 'KEY_IN_USE',
    /** From login(): the key was added to an account — sign in with that account. */
    KEY_REDEEMED: 'KEY_REDEEMED',
    /** The account already has lifetime access. */
    ALREADY_LIFETIME: 'ALREADY_LIFETIME',
    /** Account sign-up: the username is taken. */
    USERNAME_EXISTS: 'USERNAME_EXISTS',

    /** The server could not verify the request: the wrong app secret, or a clock far off. */
    CRYPTO_ERROR: 'CRYPTO_ERROR',

    /**
     * Raised by the client itself, never by the server: the heartbeat could not reach
     * the license server for `maxHeartbeatFailures` beats in a row. Without this, blocking
     * the license domain in a firewall would keep a revoked application running forever.
     */
    NETWORK_LOST: 'NETWORK_LOST',

    /**
     * Raised by the client itself: the server refused `maxHeartbeatFailures` beats in a row
     * because this computer's clock is wrong (only with `autoCorrectClock: false`; by
     * default the client repairs the clock). Ask the user to fix the date and time.
     */
    CLOCK_SKEW: 'CLOCK_SKEW',
});

const SESSION_ENDING = new Set([
    PwfErrorCodes.BANNED,
    PwfErrorCodes.PAUSED,
    PwfErrorCodes.EXPIRED,
    PwfErrorCodes.INVALID_KEY,
    PwfErrorCodes.HWID_MISMATCH,
    PwfErrorCodes.HWID_RESET,
    PwfErrorCodes.MAINTENANCE,
    PwfErrorCodes.SESSION_EXPIRED,
    PwfErrorCodes.SESSION_MISMATCH,
    PwfErrorCodes.SESSION_REVOKED,
    PwfErrorCodes.NETWORK_LOST,
    PwfErrorCodes.CLOCK_SKEW,
]);

/**
 * True when this code means the session is over and the app must sign the user out.
 * @param {string|null|undefined} errorCode
 */
export function endsSession(errorCode) {
    return !!errorCode && SESSION_ENDING.has(errorCode);
}
