// 1.1.0: the kill switch cannot be dodged, a fake plain "success" is refused, a wrong
// clock repairs itself, and the new calls (resetHardwareId, registerAccountWithKey,
// redeemKey) send what the server reads. Real loopback server, real envelope.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
    CryptoEnvelope, PwfClient, PwfError, PwfErrorCodes, PwfHttpError, PwfSecurityError,
    VERSION, endsSession,
} from '../src/index.js';

const SECRET = 'c'.repeat(64);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * handler({path, body, raw, count, headers}) returns
 *   { json, status?, plain? }  — plain: send the JSON unencrypted.
 */
async function withServer(handler, fn, { serverOffset = 0 } = {}) {
    const env = new CryptoEnvelope(SECRET);
    env.clockOffsetSeconds = serverOffset;   // the test server's own clock stays right
    const seen = [];
    const server = createServer((req, res) => {
        let raw = '';
        req.on('data', (c) => { raw += c; });
        req.on('end', () => {
            let body = {};
            try {
                body = raw && CryptoEnvelope.looksLikeEnvelope(raw)
                    ? JSON.parse(env.decrypt(raw))
                    : (raw ? JSON.parse(raw) : {});
            } catch { body = null; }         // e.g. a request stamped by a wrong clock
            seen.push({ path: req.url, method: req.method, headers: req.headers, body, raw });
            const out = handler({ path: req.url, body, raw, count: seen.length, headers: req.headers });
            const payload = JSON.stringify(out.json);
            res.writeHead(out.status ?? 200, { 'Content-Type': 'application/json' });
            res.end(out.plain ? payload : env.encrypt(payload));
        });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
        return await fn({ baseUrl, seen });
    } finally {
        server.closeAllConnections?.();
        await new Promise((r) => server.close(r));
    }
}

const okLogin = { success: true, session_id: 's', heartbeat_interval: 30 };

function client(baseUrl, extra = {}) {
    return new PwfClient({ appSecret: SECRET, baseUrl, hardwareId: 'H1', ...extra });
}

/** Login, run the loop, resolve with the sessionEnded event (or null after `wait` ms). */
async function runUntilEnded(c, wait = 3000) {
    await c.login('K');
    c.heartbeatIntervalSeconds = 0.02;
    const ended = new Promise((r) => c.once('sessionEnded', r));
    c.startHeartbeat();
    const e = await Promise.race([ended, sleep(wait).then(() => null)]);
    c.stopHeartbeat();
    return e;
}

const beatRoute = (beat) => ({ path, count }) => (path === '/api/auth/login.php' ? { json: okLogin } : beat(count));

// ── the kill switch cannot be dodged ──

test('plain clock refusals end the session with CLOCK_SKEW (auto-correct off)', async () => {
    await withServer(beatRoute(() => ({ plain: true, status: 400,
        json: { success: false, error_code: 'CRYPTO_ERROR', message: 'Request expired' } })), async ({ baseUrl }) => {
        const e = await runUntilEnded(client(baseUrl, { autoCorrectClock: false }));
        assert.ok(e, 'a moved clock kept the session alive (the 1.0.0 bypass)');
        assert.equal(e.errorCode, PwfErrorCodes.CLOCK_SKEW);
    });
});

test('other plain refusals end the session with NETWORK_LOST', async () => {
    await withServer(beatRoute(() => ({ plain: true, status: 401,
        json: { success: false, error_code: 'INVALID_APP', message: 'Invalid app secret.' } })), async ({ baseUrl }) => {
        const e = await runUntilEnded(client(baseUrl));
        assert.equal(e?.errorCode, PwfErrorCodes.NETWORK_LOST);
    });
});

test('a forged plain success in the heartbeat counts as unanswered', async () => {
    await withServer(beatRoute(() => ({ plain: true, json: { success: true } })), async ({ baseUrl }) => {
        const e = await runUntilEnded(client(baseUrl));
        assert.equal(e?.errorCode, PwfErrorCodes.NETWORK_LOST, 'a fake plain success kept the app running');
    });
});

test('rate limits have their own, larger budget', async () => {
    let beats = 0;
    await withServer(beatRoute(() => { beats++; return { plain: true, status: 429, json: { success: false, error_code: 'RATE_LIMITED' } }; }),
        async ({ baseUrl }) => {
            const e = await runUntilEnded(client(baseUrl, { maxHeartbeatFailures: 2, maxRateLimitedBeats: 6 }));
            assert.equal(e?.errorCode, PwfErrorCodes.NETWORK_LOST);
            assert.ok(beats >= 6, `429 used the smaller budget (${beats} beats)`);
        });
});

test('an encrypted answer resets the failure count', async () => {
    await withServer(beatRoute((count) => (count % 2
        ? { plain: true, status: 400, json: { success: false, error_code: 'CRYPTO_ERROR', message: 'bad' } }
        : { json: { success: true } })), async ({ baseUrl }) => {
        const e = await runUntilEnded(client(baseUrl, { maxHeartbeatFailures: 2 }), 500);
        assert.equal(e, null, 'single misses between good beats must not end the session');
    });
});

test('the server kill codes end the session', () => {
    for (const code of ['BANNED', 'PAUSED', 'EXPIRED', 'HWID_RESET', 'MAINTENANCE',
        'SESSION_REVOKED', 'SESSION_EXPIRED', 'SESSION_MISMATCH', 'NETWORK_LOST', 'CLOCK_SKEW']) {
        assert.equal(endsSession(code), true, code);
    }
    assert.equal(endsSession('RATE_LIMITED'), false);
});

test('no sessionEnded after logout while a beat is in flight', async () => {
    await withServer(({ path }) => {
        if (path === '/api/auth/login.php') return { json: okLogin };
        if (path === '/api/auth/logout.php') return { json: { success: true } };
        return { plain: true, status: 400, json: { success: false, error_code: 'CRYPTO_ERROR', message: 'x' } };
    }, async ({ baseUrl }) => {
        const c = client(baseUrl, { maxHeartbeatFailures: 1 });
        await c.login('K');
        c.heartbeatIntervalSeconds = 0.001;
        let fired = false;
        c.on('sessionEnded', () => { fired = true; });
        c.startHeartbeat();
        await sleep(1);                    // a beat is now in flight
        await c.logout();
        await sleep(200);
        assert.equal(fired, false, 'sessionEnded fired after the user logged out');
    });
});

// ── a fake server is refused ──

test('login refuses a plain success', async () => {
    await withServer(() => ({ plain: true, json: { success: true, session_id: 'fake' } }), async ({ baseUrl }) => {
        const c = client(baseUrl);
        await assert.rejects(c.login('ANY'), PwfSecurityError);
        assert.equal(c.isSignedIn, false);
    });
});

test('app info refuses a plain success', async () => {
    await withServer(() => ({ plain: true, json: { success: true, app: {} } }), async ({ baseUrl }) => {
        await assert.rejects(client(baseUrl).getAppInfo(), PwfSecurityError);
    });
});

test('plain refusals are still returned, a 401 without the API shape rejects', async () => {
    await withServer(({ count }) => (count === 1
        ? { plain: true, status: 400, json: { success: false, error_code: 'INVALID_KEY', message: 'Invalid key.' } }
        : { plain: true, status: 401, json: { detail: 'nope' } }), async ({ baseUrl }) => {
        const c = client(baseUrl);
        const r = await c.login('NOPE');
        assert.equal(r.success, false);
        assert.equal(r.errorCode, 'INVALID_KEY');
        await assert.rejects(c.login('K'), (e) => e instanceof PwfHttpError && e.status === 401);
    });
});

// ── a wrong clock repairs itself ──

test('a wrong clock is corrected and the request retried once', async () => {
    const serverNow = Math.floor(Date.now() / 1000);
    await withServer(({ raw }) => (Math.abs(JSON.parse(raw).t - serverNow) > 300
        ? { plain: true, status: 400, json: { success: false, error_code: 'CRYPTO_ERROR', reason: 'CLOCK_SKEW', server_time: serverNow, message: 'expired' } }
        : { json: okLogin }), async ({ baseUrl, seen }) => {
        const c = client(baseUrl);
        const realNow = Date.now;
        Date.now = () => realNow() - 9 * 3600 * 1000;      // this PC is 9 hours behind
        try {
            const r = await c.login('K');
            assert.equal(r.success, true);
        } finally {
            Date.now = realNow;
        }
        assert.equal(seen.length, 2, 'exactly one retry');
        assert.ok(Math.abs(c.clockOffsetSeconds - 9 * 3600) <= 5, `offset ${c.clockOffsetSeconds}`);
    }, { serverOffset: 9 * 3600 });           // Date.now is moved back below; the server is not
});

test('no retry when auto-correct is off, and only one retry per call', async () => {
    const reply = () => ({ plain: true, status: 400, json: { success: false, error_code: 'CRYPTO_ERROR', reason: 'CLOCK_SKEW', server_time: 1000, message: 'expired' } });
    await withServer(reply, async ({ baseUrl, seen }) => {
        await client(baseUrl, { autoCorrectClock: false }).login('K');
        assert.equal(seen.length, 1);
        await client(baseUrl).login('K');
        assert.equal(seen.length, 3);
    });
});

// ── new calls ──

test('resetHardwareId sends key + reason, plain, with a default and a 255 cap', async () => {
    await withServer(() => ({ plain: true, json: { success: true, next_reset_at: '2026-10-06T00:00:00Z' } }), async ({ baseUrl, seen }) => {
        const c = client(baseUrl);
        const r = await c.resetHardwareId(' K-1 ', 'New laptop');
        assert.equal(r.success, true);
        assert.equal(seen[0].path, '/api/customer/reset-hwid.php');
        assert.deepEqual(seen[0].body, { key: 'K-1', reason: 'New laptop' });
        assert.equal(CryptoEnvelope.looksLikeEnvelope(seen[0].raw), false);
        await c.resetHardwareId('K');
        assert.equal(seen[1].body.reason, 'Reset from app');
        await c.resetHardwareId('K', '😀'.repeat(300));
        assert.equal(Array.from(seen[2].body.reason).length, 255);
        await assert.rejects(c.resetHardwareId(''), TypeError);
    });
});

test('registerAccountWithKey and registerAccount', async () => {
    await withServer(() => ({ plain: true, json: { success: true } }), async ({ baseUrl, seen }) => {
        const c = client(baseUrl);
        await c.registerAccount('bob', 'pw', 'b@x.io');
        assert.deepEqual(seen[0].body, { username: 'bob', password: 'pw', email: 'b@x.io' });
        await c.registerAccountWithKey('bob', 'pw', ' K-9 ');
        assert.deepEqual(seen[1].body, { username: 'bob', password: 'pw', email: '', license_key: 'K-9' });
        await assert.rejects(c.registerAccountWithKey('bob', 'pw', ''), TypeError);
    });
});

test('redeemKey with the password, or through the account session', async () => {
    await withServer(({ path }) => (path === '/api/auth/account-login.php'
        ? { plain: true, json: { success: true, session_id: 'acc-1', heartbeat_interval: 30 } }
        : { plain: true, json: { success: true, days_added: 30 } }), async ({ baseUrl, seen }) => {
        const c = client(baseUrl);
        await c.redeemKey('K-1', 'bob', 'pw');
        assert.deepEqual(seen[0].body, { username: 'bob', password: 'pw', license_key: 'K-1' });
        await assert.rejects(c.redeemKey('K-1'), PwfError);               // nobody signed in
        await assert.rejects(c.redeemKey('K-1', 'bob'), TypeError);       // half the credentials
        await c.accountLogin('bob', 'pw');
        await c.redeemKey('K-2');
        assert.deepEqual(seen.at(-1).body, { session_id: 'acc-1', license_key: 'K-2' });
    });
});

test('checkUpdate sends v + channel; trackSocialClick needs a numeric id', async () => {
    await withServer(() => ({ json: { success: true, update_available: false } }), async ({ baseUrl, seen }) => {
        const c = client(baseUrl);
        await c.checkUpdate('1.4.2', 'beta');
        assert.equal(seen[0].body.v, '1.4.2');
        assert.equal(seen[0].body.channel, 'beta');
        await c.trackSocialClick(7);
        assert.deepEqual(seen[1].body, { link_id: 7 });
        await assert.rejects(c.trackSocialClick('discord'), TypeError);
    });
});

test('a User-Agent with the version goes on every request', async () => {
    await withServer(() => ({ json: { success: true } }), async ({ baseUrl, seen }) => {
        await client(baseUrl).getAppInfo();
        assert.equal(seen[0].headers['user-agent'], `pwfauth-node/${VERSION} (+https://pwfauth.com)`);
        assert.equal(VERSION, '1.1.0');
    });
});

test('no connection: the message says so (not "did not respond in time")', async () => {
    const c = new PwfClient({ appSecret: SECRET, baseUrl: 'http://127.0.0.1:9', hardwareId: 'H1', timeoutMs: 2000 });
    await assert.rejects(c.getAppInfo(), (e) => e instanceof PwfHttpError && e.status === 0 && /Cannot reach/.test(e.message));
});

test('options are validated', () => {
    assert.throws(() => new PwfClient({ appSecret: SECRET, baseUrl: 'pwfauth.com' }), TypeError);
    assert.throws(() => new PwfClient({ appSecret: SECRET, maxHeartbeatFailures: 0 }), RangeError);
    assert.throws(() => new PwfClient({ appSecret: SECRET, maxRateLimitedBeats: 0 }), RangeError);
});
