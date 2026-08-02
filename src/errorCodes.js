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

    /**
     * Raised by the client itself, never by the server: the heartbeat could not reach
     * the license server for `maxHeartbeatFailures` beats in a row. Without this, blocking
     * the license domain in a firewall would keep a revoked application running forever.
     */
    NETWORK_LOST: 'NETWORK_LOST',
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
]);

/**
 * True when this code means the session is over and the app must sign the user out.
 * @param {string|null|undefined} errorCode
 */
export function endsSession(errorCode) {
    return !!errorCode && SESSION_ENDING.has(errorCode);
}
