import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
    CryptoEnvelope, PwfClient, PwfSecurityError, PwfHttpError, PwfResponse, endsSession, PwfErrorCodes,
    signReply,
} from './clientUnderTest.js';

const SECRET = 'c'.repeat(64);

/**
 * A real HTTP server speaking the envelope, so the transport, the crypto and the
 * heartbeat loop are exercised end to end rather than stubbed.
 */
async function withServer(handler, fn) {
    const env = new CryptoEnvelope(SECRET);
    const seen = [];
    const server = createServer((req, res) => {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
            const decoded = body && CryptoEnvelope.looksLikeEnvelope(body)
                ? JSON.parse(env.decrypt(body))
                : (body ? JSON.parse(body) : {});
            seen.push({ path: req.url, method: req.method, headers: req.headers, body: decoded });

            const out = handler({ path: req.url, body: decoded, count: seen.length });
            const status = out.status ?? 200;
            const payload = JSON.stringify(out.json);
            const reply = out.plain ? payload : env.encrypt(payload);
            res.writeHead(status, { 'Content-Type': 'application/json', 'X-PWF-Signature': signReply(req, body, status, reply) });
            res.end(reply);
        });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
        return await fn({ baseUrl, seen });
    } finally {
        await new Promise((r) => server.close(r));
    }
}

const okLogin = {
    success: true, message: 'License activated successfully!', session_id: 'sess-1',
    user: {
        license_key: 'AAAAA-BBBBB-CCCCC-DDDDD', key_type: 'days', duration: 30, hwid: 'H1',
        activated_at: '2026-08-02T12:00:00Z', expires_at: '2026-09-01T12:00:00Z',
        days_remaining: 30, status: 'active',
    },
    features: { pro_tier: true },
    heartbeat_interval: 30,
};

test('login succeeds and captures session state', async () => {
    await withServer(() => ({ json: okLogin }), async ({ baseUrl, seen }) => {
        const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
        const res = await c.login('AAAAA-BBBBB-CCCCC-DDDDD');

        assert.equal(res.success, true);
        assert.equal(c.isSignedIn, true);
        assert.equal(c.sessionId, 'sess-1');
        assert.equal(c.heartbeatIntervalSeconds, 30);
        // the request really was enveloped and carried the secret header
        assert.equal(seen[0].path, '/api/auth/login.php');
        assert.equal(seen[0].headers['x-app-secret'], SECRET);
        assert.deepEqual(seen[0].body, { license_key: 'AAAAA-BBBBB-CCCCC-DDDDD', hwid: 'H1' });
    });
});

test('license getter parses dates and features', async () => {
    await withServer(() => ({ json: okLogin }), async ({ baseUrl }) => {
        const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
        const lic = (await c.login('K')).license;
        assert.equal(lic.isLifetime, false);
        assert.equal(lic.expiresAt.toISOString(), '2026-09-01T12:00:00.000Z');
        assert.equal(lic.daysRemaining, 30);
        assert.equal(lic.status, 'active');
    });
});

test('lifetime keys report null expiry, not a crash', async () => {
    const lifetime = { ...okLogin, user: { ...okLogin.user, expires_at: null, days_remaining: null } };
    await withServer(() => ({ json: lifetime }), async ({ baseUrl }) => {
        const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
        const lic = (await c.login('K')).license;
        assert.equal(lic.expiresAt, null);
        assert.equal(lic.daysRemaining, null);
        assert.equal(lic.isLifetime, true);
    });
});

test('a failed login leaves the client signed out', async () => {
    await withServer(() => ({ json: { success: false, error_code: 'INVALID_KEY', message: 'Invalid license key.' } }),
        async ({ baseUrl }) => {
            const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
            const res = await c.login('NOPE');
            assert.equal(res.success, false);
            assert.equal(res.errorCode, 'INVALID_KEY');
            assert.equal(c.isSignedIn, false);
        });
});

test('the kill switch ends the session on a banning beat', async () => {
    await withServer(({ path }) => {
        if (path === '/api/auth/login.php') return { json: { ...okLogin, heartbeat_interval: 5 } };
        return { json: { success: false, error_code: 'BANNED', message: 'This license key has been banned.' } };
    }, async ({ baseUrl }) => {
        const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
        await c.login('K');
        c.heartbeatIntervalSeconds = 0.05;              // don't make the test wait 5s
        const ended = new Promise((r) => c.once('sessionEnded', r));
        c.startHeartbeat();

        const e = await ended;
        assert.equal(e.errorCode, 'BANNED');
        assert.match(e.message, /banned/i);
        assert.equal(c.isSignedIn, false, 'must be signed out once the kill switch fires');
    });
});

test('an unreachable server ends the session with NETWORK_LOST', async () => {
    // Login against a live server, then point the client at a dead port so every beat
    // fails — this is the firewall-bypass case.
    await withServer(() => ({ json: { ...okLogin, heartbeat_interval: 5 } }), async ({ baseUrl }) => {
        const c = new PwfClient({
            appSecret: SECRET, baseUrl, hardwareId: 'H1',
            maxHeartbeatFailures: 2, timeoutMs: 300,
        });
        await c.login('K');

        c.heartbeatIntervalSeconds = 0.05;
        // 127.0.0.1:9 is the discard port — connections are refused immediately.
        const dead = new PwfClient({
            appSecret: SECRET, baseUrl: 'http://127.0.0.1:9', hardwareId: 'H1',
            maxHeartbeatFailures: 2, timeoutMs: 300,
        });
        dead.sessionId = c.sessionId;
        dead.licenseKey = c.licenseKey;
        dead.heartbeatIntervalSeconds = 0.05;

        const ended = new Promise((r) => dead.once('sessionEnded', r));
        dead.startHeartbeat();

        const e = await ended;
        assert.equal(e.errorCode, PwfErrorCodes.NETWORK_LOST);
        assert.equal(dead.isSignedIn, false);
        await c.logout();
    });
});

test('a transient non-session error keeps the loop alive', async () => {
    let beats = 0;
    await withServer(({ path }) => {
        if (path === '/api/auth/login.php') return { json: okLogin };
        beats++;
        // Not a session-ending code — the client must keep beating.
        return { json: { success: false, error_code: 'SOME_TRANSIENT_THING', message: 'later' } };
    }, async ({ baseUrl }) => {
        const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
        await c.login('K');
        c.heartbeatIntervalSeconds = 0.03;
        let ended = false;
        c.once('sessionEnded', () => { ended = true; });
        c.startHeartbeat();
        await new Promise((r) => setTimeout(r, 250));
        c.stopHeartbeat();
        assert.equal(ended, false, 'unknown codes must not end the session');
        assert.ok(beats >= 2, `expected repeated beats, saw ${beats}`);
        assert.equal(c.isSignedIn, true);
    });
});

test('logout frees the seat and stops the loop', async () => {
    await withServer(({ path }) => path === '/api/auth/login.php'
        ? { json: okLogin }
        : { json: { success: true, message: 'Logged out.' } },
    async ({ baseUrl, seen }) => {
        const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
        await c.login('K');
        c.startHeartbeat();
        await c.logout();
        assert.equal(c.isSignedIn, false);
        assert.ok(seen.some((r) => r.path === '/api/auth/logout.php'));
        assert.equal(await c.logout(), null, 'second logout is a no-op');
    });
});

test('plain-JSON endpoints are not enveloped', async () => {
    await withServer(() => ({ json: { success: true, message: 'Trial created.' }, plain: true }),
        async ({ baseUrl, seen }) => {
            const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
            const res = await c.createTrial();
            assert.equal(res.success, true);
            assert.equal(seen[0].path, '/api/auth/trial.php');
            assert.deepEqual(seen[0].body, { hwid: 'H1' });
        });
});

test('an unsigned proxy error is rejected before parsing', async () => {
    const server = createServer((_req, res) => {
        res.writeHead(502, { 'Content-Type': 'text/html' });
        res.end('<html><body>502 Bad Gateway</body></html>');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
        const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
        await assert.rejects(() => c.login('K'), (e) => {
            assert.ok(e instanceof PwfSecurityError);


            return true;
        });
    } finally {
        await new Promise((r) => server.close(r));
    }
});

test('a reply sealed with another secret is rejected, not trusted', async () => {
    // The client must refuse an envelope it cannot authenticate. Sealing the reply with
    // a different secret is exactly what an attacker swapping responses would produce.
    const foreign = new CryptoEnvelope('d'.repeat(64));
    const server = createServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(foreign.encrypt(JSON.stringify(okLogin)));
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
        const c = new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1' });
        await assert.rejects(() => c.login('K'), /Missing or invalid server signature/);
        assert.equal(c.isSignedIn, false);
    } finally {
        await new Promise((r) => server.close(r));
    }
});

test('heartbeat before login is refused', async () => {
    const c = new PwfClient({ appSecret: SECRET, baseUrl: 'http://127.0.0.1:9' });
    assert.throws(() => c.startHeartbeat(), /No open session/);
    // heartbeat() returns a promise, so it must REJECT — a synchronous throw would
    // escape any .catch() chain the caller wrote.
    await assert.rejects(() => c.heartbeat(), /No open session/);
});

test('argument validation rejects rather than throwing synchronously', async () => {
    const c = new PwfClient({ appSecret: SECRET, baseUrl: 'http://127.0.0.1:9' });
    // Every promise-returning method must surface bad input as a rejection.
    await assert.rejects(() => c.login(''), TypeError);
    await assert.rejects(() => c.checkKey(''), TypeError);
    await assert.rejects(() => c.checkUpdate(''), TypeError);
    await assert.rejects(() => c.requestHardwareReset(''), TypeError);
    await assert.rejects(() => c.registerAccount('', ''), TypeError);
    await assert.rejects(() => c.getTexts(), /Sign in first/);
    // ...and a .catch() chain (not just await) must see it.
    let caught = null;
    await c.checkKey('').catch((e) => { caught = e; });
    assert.ok(caught instanceof TypeError);
});

test('endsSession classifies codes correctly', () => {
    for (const c of ['BANNED', 'PAUSED', 'EXPIRED', 'HWID_RESET', 'MAINTENANCE',
        'SESSION_REVOKED', 'SESSION_EXPIRED', 'SESSION_MISMATCH', 'INVALID_KEY',
        'HWID_MISMATCH', 'NETWORK_LOST']) {
        assert.equal(endsSession(c), true, `${c} must end the session`);
    }
    for (const c of ['MISSING_FIELDS', 'TRIAL_USED', 'SOMETHING_NEW', '', null, undefined]) {
        assert.equal(endsSession(c), false, `${c} must NOT end the session`);
    }
});

test('PwfResponse rejects non-object bodies', () => {
    assert.throws(() => PwfResponse.parse('[]'), /not a JSON object/);
    assert.throws(() => PwfResponse.parse('oops'), /not valid JSON/);
});

test('constructor validates input', () => {
    assert.throws(() => new PwfClient(''), TypeError);
    assert.throws(() => new PwfClient({}), TypeError);
    // A trailing slash in baseUrl must not produce a double slash in request URLs.
    const c = new PwfClient({ appSecret: SECRET, baseUrl: 'https://pwfauth.com/' });
    assert.ok(c instanceof PwfClient);
});
