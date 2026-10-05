/** Base class for every error this client raises. */
export class PwfError extends Error {
    constructor(message, options) {
        super(message, options);
        this.name = 'PwfError';
    }
}

/** The license server answered, but not with a usable API reply. */
export class PwfHttpError extends PwfError {
    /**
     * @param {number} status          HTTP status, or 0 when the request never completed.
     * @param {string} message         Human-readable explanation.
     * @param {string} responseSnippet First part of the body, for diagnosis.
     */
    constructor(status, message, responseSnippet = '', options) {
        super(message, options);
        this.name = 'PwfHttpError';
        this.status = status;
        this.responseSnippet = responseSnippet;
    }
}

/** The envelope failed to verify or decrypt. Almost always the wrong app secret. */
export class PwfCryptoError extends PwfError {
    constructor(message, options) {
        super(message, options);
        this.name = 'PwfCryptoError';
    }
}

/**
 * An encrypted endpoint answered with an UNENCRYPTED "success". The license server
 * encrypts every reply of these endpoints once it has accepted the app secret; only
 * refusals travel as plain JSON. A plain success therefore did not come from PWF Auth —
 * a proxy, a hosts-file redirect or a fake server sent it. Never unlock the app on it.
 */
export class PwfSecurityError extends PwfError {
    constructor(message, options) {
        super(message, options);
        this.name = 'PwfSecurityError';
    }
}
